// What the web app shows while the realm is closed and the server is directory-only, through the
// gate's headless browser. Each step prints what it saw (ROW <name> SEEN <what>) and the phase
// judges it. BROWSER_MODE admin: the admins' notice, the sync switch on the create-user page, a
// create with it, the switch on BROWSER_SYNCED's page and a save of another attribute there; user:
// BROWSER_USER's own page, where there is no notice. sign-in-actions.mjs is the model.

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";

const outDir = process.env.BROWSER_OUT || "/out";
const base = process.env.BROWSER_URL;
const mode = process.env.BROWSER_MODE || "";
const adminPass = process.env.BROWSER_ADMIN_PASS || "";
const userPass = process.env.BROWSER_PASS || "";
const user = process.env.BROWSER_USER || "";
const synced = process.env.BROWSER_SYNCED || "";
const fresh = process.env.BROWSER_NEW || "";
const secrets = [adminPass, userPass].filter((s) => s.length > 0);
const WAIT_MS = 30000;
const NOTICE = "kerberos-notice";

const consoleLines = [];
const infoAsks = new Set();
let infoAnswers = 0;
let chrome;
let ws;
let nextId = 0;
let currentStep = mode;
const pending = new Map();

function say(line) {
  process.stdout.write(`${line}\n`);
}

function redact(text) {
  let out = String(text ?? "");
  for (const secret of secrets) out = out.split(secret).join("[redacted]");
  return out;
}

function row(name, kind, detail) {
  const clean = redact(detail || "").replace(/\s+/g, " ").trim().slice(0, 700);
  say(`ROW ${name} ${kind}${clean ? ` ${clean}` : ""}`);
}

function fail(selector, detail) {
  const err = new Error(redact(detail || selector));
  err.selector = selector;
  return err;
}

function chromeBin() {
  const root = "/ms-playwright";
  const dirs = readdirSync(root).filter((name) => /^chromium-\d+$/.test(name));
  if (dirs.length === 0) throw fail("chrome", "no chromium under /ms-playwright");
  return `${root}/${dirs[0]}/chrome-linux64/chrome`;
}

function send(method, params = {}) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(fail(method, `CDP ${method} timed out`));
    }, WAIT_MS);
    pending.set(id, {
      resolve: (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      reject: (err) => {
        clearTimeout(timer);
        reject(err);
      },
    });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

// The pages' own read of the realm's state, GetKerberosInfo: counted when its answer has arrived.
function onNetwork(msg) {
  if (msg.method === "Network.requestWillBeSent") {
    const req = msg.params.request || {};
    if (String(req.url).endsWith("/api/graphql") && String(req.postData || "").includes("GetKerberosInfo")) {
      infoAsks.add(msg.params.requestId);
    }
  } else if (msg.method === "Network.loadingFinished" || msg.method === "Network.loadingFailed") {
    if (infoAsks.delete(msg.params.requestId)) infoAnswers += 1;
  }
}

function onMessage(raw) {
  const msg = JSON.parse(raw.data);
  if (msg.id && pending.has(msg.id)) {
    const waiter = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) waiter.reject(fail(msg.method || "cdp", msg.error.message));
    else waiter.resolve(msg.result);
    return;
  }
  if (String(msg.method).startsWith("Network.")) {
    onNetwork(msg);
  } else if (msg.method === "Runtime.consoleAPICalled") {
    consoleLines.push(redact((msg.params.args || []).map((a) => a.value ?? a.description ?? a.type).join(" ")));
  } else if (msg.method === "Runtime.exceptionThrown") {
    consoleLines.push(redact(msg.params.exceptionDetails?.text || "exception"));
  }
}

async function evalValue(expression) {
  const result = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (result.exceptionDetails) throw fail("evaluate", result.exceptionDetails.text || "evaluate failed");
  return result.result?.value;
}

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(expression, selector, timeoutMs = WAIT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await evalValue(expression)) return;
    } catch {
      // The page is still loading.
    }
    await pause(200);
  }
  throw fail(selector, `waited for ${selector}`);
}

async function fill(selector, value) {
  await waitFor(`!!document.querySelector(${JSON.stringify(selector)})`, selector);
  const ok = await evalValue(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
    proto.set.call(el, ${JSON.stringify(value)});
    el.dispatchEvent(new InputEvent("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return el.value === ${JSON.stringify(value)};
  })()`);
  if (!ok) throw fail(selector, "the value did not take");
}

async function click(label) {
  const find = `[...document.querySelectorAll("button")].find((b) =>
    b.textContent.includes(${JSON.stringify(label)}) && !b.disabled)`;
  await waitFor(`!!${find}`, `button ${label}`);
  await evalValue(`${find}.click()`);
}

// A page that reads the realm's state is read only once that answer has arrived.
async function goto(path, readsState) {
  const before = infoAnswers;
  await send("Page.navigate", { url: `${base}${path}` });
  await waitFor(`location.pathname === ${JSON.stringify(path)}`, `path ${path}`);
  if (!readsState) return;
  const deadline = Date.now() + WAIT_MS;
  while (infoAnswers === before && Date.now() < deadline) await pause(200);
  if (infoAnswers === before) throw fail("GetKerberosInfo", `no Kerberos state answer on ${path}`);
  await pause(500);
}

async function login(who, password) {
  await goto("/login", false);
  await fill("#username", who);
  await fill("#password", password);
  await click("Login");
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes("Logout"))`,
    "button Logout",
  );
}

async function notice() {
  return evalValue(`(() => {
    const el = document.getElementById(${JSON.stringify(NOTICE)});
    return el ? el.textContent.replace(/\\s+/g, " ").trim() : "none";
  })()`);
}

// The Kerberos Sync row: each button as disabled or enabled and active or idle, then the hint. A
// page may draw the row before its read of the state has answered: a locked switch is waited for
// ten seconds, and the row says what is there then.
async function syncSwitch() {
  const rowExpr = `document.querySelector('label[for="kerberossync_toggle"]')?.closest(".row")`;
  await waitFor(`!!${rowExpr}`, "the Kerberos Sync row");
  try {
    await waitFor(`${rowExpr}?.querySelector(".btn-group button")?.disabled === true`, "a locked switch", 10000);
  } catch {
    // The row says it is not locked.
  }
  return evalValue(`(() => {
    const row = ${rowExpr};
    const state = (label) => {
      const b = [...row.querySelectorAll(".btn-group button")].find((x) => x.textContent.trim() === label);
      if (!b) return label + "=none";
      return label + "=" + (b.disabled ? "disabled" : "enabled") + "," + (b.classList.contains("active") ? "active" : "idle");
    };
    const hint = (row.querySelector(".form-text")?.textContent || "").replace(/\\s+/g, " ").trim();
    return state("On") + " " + state("Off") + " | " + hint;
  })()`);
}

async function adminPages() {
  currentStep = "notice-admin";
  await login("admin", adminPass);
  await goto("/users", true);
  try {
    await waitFor(`!!document.getElementById(${JSON.stringify(NOTICE)})`, `#${NOTICE}`, 10000);
  } catch {
    // The row says it is not there.
  }
  row("notice-admin", "SEEN", await notice());

  currentStep = "create-switch";
  await goto("/users/create", true);
  await waitFor(`!!document.querySelector("input[name=mail]")`, "input[name=mail]");
  row("create-switch", "SEEN", await syncSwitch());

  currentStep = "create-submit";
  await fill("#username", fresh);
  await fill("input[name=mail]", `${fresh}@gate.test`);
  await fill("#password", userPass);
  await fill("#confirm_password", userPass);
  await click("Submit");
  try {
    await waitFor(`location.pathname === "/users"`, "path /users");
    row("create-submit", "SEEN", "path /users");
  } catch {
    const said = await evalValue(`(document.querySelector(".alert-danger")?.textContent || "no alert").trim()`);
    row("create-submit", "SEEN", `path ${await evalValue("location.pathname")} | ${said}`);
  }

  currentStep = "details-switch";
  await goto(`/user/${synced}`, true);
  await waitFor(`[...document.querySelectorAll("h3")].some((h) => h.textContent.trim() === ${JSON.stringify(synced)})`, `h3 ${synced}`);
  row("details-switch", "SEEN", await syncSwitch());

  currentStep = "details-save";
  await fill("input[name=display_name]", `${synced} saved`);
  await click("Save changes");
  await waitFor(
    `!!document.querySelector(".alert-danger") || [...document.querySelectorAll(".alert-success")].some((a) => !a.closest("[hidden]"))`,
    "the save's answer",
  );
  const saved = await evalValue(`(() => {
    const bad = document.querySelector(".alert-danger");
    if (bad) return bad.textContent.trim();
    const ok = [...document.querySelectorAll(".alert-success")].find((a) => !a.closest("[hidden]"));
    return ok ? ok.textContent.trim() : "no answer";
  })()`);
  row("details-save", "SEEN", saved);
}

// A regular user's pages do not ask for the realm's state at all: the page is given two seconds.
async function userPage() {
  currentStep = "notice-user";
  await login(user, userPass);
  await goto(`/user/${user}`, false);
  await waitFor(`[...document.querySelectorAll("h3")].some((h) => h.textContent.trim() === ${JSON.stringify(user)})`, `h3 ${user}`);
  await pause(2000);
  row("notice-user", "SEEN", await notice());
}

async function connect() {
  const home = process.env.HOME || "/tmp/home";
  await mkdir(home, { recursive: true });
  await mkdir("/tmp/chrome-user", { recursive: true });
  chrome = spawn(
    chromeBin(),
    [
      "--headless=new",
      "--no-sandbox",
      "--disable-gpu",
      "--remote-debugging-port=9222",
      "--remote-debugging-address=127.0.0.1",
      "--remote-allow-origins=*",
      "--user-data-dir=/tmp/chrome-user",
      "--no-first-run",
      "--no-default-browser-check",
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );
  chrome.stderr.on("data", (chunk) => consoleLines.push(redact(chunk.toString())));
  const deadline = Date.now() + WAIT_MS;
  let page;
  while (Date.now() < deadline) {
    try {
      const list = await (await fetch("http://127.0.0.1:9222/json/list")).json();
      page = list.find((target) => target.type === "page" && target.webSocketDebuggerUrl);
      if (page) break;
    } catch {
      // The port is not up yet.
    }
    await pause(200);
  }
  if (!page) throw fail("chrome", "debug port");
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", () => reject(fail("chrome", "debug socket")), { once: true });
  });
  ws.addEventListener("message", onMessage);
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable", { maxPostDataSize: 65536 });
}

let failed = false;
try {
  await connect();
  if (mode === "admin" && synced && fresh) await adminPages();
  else if (mode === "user" && user) await userPage();
  else throw fail("BROWSER_MODE", `${mode || "unset"} or its users unset`);
} catch (err) {
  failed = true;
  row(currentStep || "mode", "FAIL", `${err.selector || "unknown"} ${err.message || ""}`);
  try {
    const shot = await send("Page.captureScreenshot", { format: "png" });
    await writeFile(`${outDir}/page-${currentStep || "mode"}.png`, Buffer.from(shot.data, "base64"));
  } catch {
    // A failed shot still leaves the row.
  }
  await writeFile(`${outDir}/page-console-${currentStep || "mode"}.txt`, consoleLines.join("\n"));
} finally {
  if (chrome && !chrome.killed) chrome.kill("SIGTERM");
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
}
process.exit(failed ? 1 : 0);
