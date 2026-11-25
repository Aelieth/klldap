// The user page's sign-in state and its buttons, through the gate's headless browser. Each step
// prints what it saw (ROW <name> SEEN <what>) and the phase judges it. BROWSER_MODE admin: the
// locked, fresh and (with BROWSER_IDLE) inactive users' pages, Unlock, and the re-enable modal's
// Cancel, once it has opened and while it opens; own: a user's own page; reenable: "Yes,
// re-enable" on the inactive user's page.
// browser-policies.mjs is the model.

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";

const outDir = process.env.BROWSER_OUT || "/out";
const base = process.env.BROWSER_URL;
const mode = process.env.BROWSER_MODE || "";
const adminPass = process.env.BROWSER_ADMIN_PASS || "";
const userPass = process.env.BROWSER_PASS || "";
const user = process.env.BROWSER_USER || "";
const locked = process.env.BROWSER_LOCKED || "";
const fresh = process.env.BROWSER_FRESH || "";
const idle = process.env.BROWSER_IDLE || "";
const secrets = [adminPass, userPass].filter((s) => s.length > 0);
const WAIT_MS = 30000;

const consoleLines = [];
const stateAsks = new Set();
let stateAnswers = 0;
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
  const clean = redact(detail || "").replace(/\s+/g, " ").trim().slice(0, 500);
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

// The page's own state read, GetSignInState: counted when its answer has arrived.
function onNetwork(msg) {
  if (msg.method === "Network.requestWillBeSent") {
    const req = msg.params.request || {};
    if (String(req.url).endsWith("/api/graphql") && String(req.postData || "").includes("GetSignInState")) {
      stateAsks.add(msg.params.requestId);
    }
  } else if (msg.method === "Network.loadingFinished" || msg.method === "Network.loadingFailed") {
    if (stateAsks.delete(msg.params.requestId)) stateAnswers += 1;
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

async function clickWithin(root, label) {
  const find = `(() => {
    const box = document.querySelector(${JSON.stringify(root)});
    return box && [...box.querySelectorAll("button")].find((b) =>
      b.textContent.includes(${JSON.stringify(label)}) && !b.disabled);
  })()`;
  await waitFor(`!!${find}`, `${root} button ${label}`);
  await evalValue(`${find}.click()`);
}

async function goto(path) {
  await send("Page.navigate", { url: `${base}${path}` });
  await waitFor(`location.pathname === ${JSON.stringify(path)}`, `path ${path}`);
}

async function login(who, password) {
  await goto("/login");
  await fill("#username", who);
  await fill("#password", password);
  await clickWithin("body", "Login");
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes("Logout"))`,
    "button Logout",
  );
}

// What the page shows of a sign-in state: each badge's and each button's text, or none.
async function seen() {
  return evalValue(`(() => {
    const t = (id) => {
      const el = document.getElementById(id);
      return el ? "'" + el.textContent.replace(/\\s+/g, " ").trim() + "'" : "none";
    };
    return "locked=" + t("sign-in-locked") + " inactive=" + t("sign-in-inactive") +
      " unlock=" + t("unlock-user") + " reenable=" + t("reenable-user");
  })()`);
}

// A user's page, read once its own state has answered (the heading comes with the admin's row).
async function openUser(id, waitState) {
  const before = stateAnswers;
  await goto(`/user/${id}`);
  await waitFor(`[...document.querySelectorAll("h3")].some((h) => h.textContent.trim() === ${JSON.stringify(id)})`, `h3 ${id}`);
  if (!waitState) return;
  const deadline = Date.now() + WAIT_MS;
  while (stateAnswers === before && Date.now() < deadline) await pause(200);
  if (stateAnswers === before) throw fail("GetSignInState", `no sign-in state answer for ${id}`);
  await pause(500);
}

async function resultLine() {
  return evalValue(`(document.getElementById("sign-in-action-result")?.textContent || "").trim()`);
}

// The result line, read in the same evaluation that finds it: the page clears it on its next message.
async function waitResult() {
  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    const line = await resultLine();
    if (line) return line;
    await pause(100);
  }
  throw fail("#sign-in-action-result", "waited for #sign-in-action-result");
}

// After an action the state is read again: wait until its badge and its button have gone.
async function gone(badge, button) {
  try {
    await waitFor(`!document.getElementById(${JSON.stringify(badge)}) && !document.getElementById(${JSON.stringify(button)})`, `${badge} gone`, 15000);
  } catch {
    // The row says what is still there.
  }
  const still = await evalValue(`[${JSON.stringify(badge)}, ${JSON.stringify(button)}].filter((id) => document.getElementById(id)).join(",")`);
  return still ? `still shown: ${still}` : "the badge and the button are gone";
}

async function adminPage() {
  currentStep = "state-locked";
  await login("admin", adminPass);
  await openUser(locked, true);
  row("state-locked", "SEEN", await seen());
  currentStep = "state-fresh";
  await openUser(fresh, true);
  row("state-fresh", "SEEN", await seen());
  if (idle) {
    currentStep = "state-inactive";
    await openUser(idle, true);
    row("state-inactive", "SEEN", await seen());
  }
  currentStep = "unlock-page";
  await openUser(locked, true);
  await waitFor(`!!document.getElementById("unlock-user")`, "#unlock-user");
  await evalValue(`document.getElementById("unlock-user").click()`);
  const unlocked = await waitResult();
  row("unlock-page", "SEEN", `${unlocked} | ${await gone("sign-in-locked", "unlock-user")}`);
  if (!idle) return;
  currentStep = "reenable-modal";
  await openUser(idle, true);
  const modal = `#reenableModal${idle}`;
  await waitFor(`!!document.getElementById("reenable-user")`, "#reenable-user");
  // Bootstrap's hide() does nothing until the opening fade has ended: Cancel waits for shown.bs.modal.
  await evalValue(`(() => {
    window.gateReenableShown = false;
    document.querySelector(${JSON.stringify(modal)}).addEventListener("shown.bs.modal", () => {
      window.gateReenableShown = true;
    }, { once: true });
    document.getElementById("reenable-user").click();
  })()`);
  await waitFor(
    `window.gateReenableShown === true && !!document.querySelector(${JSON.stringify(modal)})?.classList.contains("show")`,
    `${modal} shown`,
  );
  const text = async (sel) => evalValue(`(document.querySelector(${JSON.stringify(sel)})?.textContent || "").replace(/\\s+/g, " ").trim()`);
  const title = await text(`${modal} .modal-title`);
  const body = await text(`${modal} .modal-body`);
  await clickWithin(modal, "Cancel");
  await waitFor(`!document.querySelector(${JSON.stringify(modal)})?.classList.contains("show")`, `${modal} hidden`);
  const result = await resultLine();
  row("reenable-modal", "SEEN", `${title} | ${body} | Cancel | ${result ? `result line '${result}'` : "no result line"}`);
  currentStep = "reenable-early-cancel";
  await openUser(idle, true);
  await waitFor(`!!document.getElementById("reenable-user")`, "#reenable-user");
  // One Cancel as soon as Bootstrap begins to open (show.bs.modal), never waiting for shown.bs.modal.
  const when = await evalValue(`new Promise((resolve) => {
    const box = document.querySelector(${JSON.stringify(modal)});
    window.gateEarly = { shown: false, hidden: false };
    box.addEventListener("shown.bs.modal", () => { window.gateEarly.shown = true; }, { once: true });
    box.addEventListener("hidden.bs.modal", () => { window.gateEarly.hidden = true; }, { once: true });
    box.addEventListener("show.bs.modal", () => setTimeout(() => {
      const cancel = [...box.querySelectorAll("button")].find((b) => b.textContent.includes("Cancel"));
      const shown = window.gateEarly.shown;
      cancel.click();
      resolve(shown ? "after shown.bs.modal" : "before shown.bs.modal");
    }, 0), { once: true });
    document.getElementById("reenable-user").click();
  })`);
  await waitFor(`window.gateEarly.shown || window.gateEarly.hidden`, `${modal} opened`);
  try {
    await waitFor(`window.gateEarly.hidden`, `${modal} hidden`, 5000);
  } catch {
    // The row says what is still there.
  }
  const end = await evalValue(`(() => {
    const left = [];
    if (!window.gateEarly.hidden) left.push("no hidden.bs.modal");
    if (document.querySelector(${JSON.stringify(modal)})?.classList.contains("show")) left.push("still shown");
    if (document.querySelector(".modal-backdrop")) left.push("backdrop left");
    if (document.body.classList.contains("modal-open")) left.push("body still modal-open");
    return left.length ? left.join(", ") : "closed";
  })()`);
  const early = await resultLine();
  row("reenable-early-cancel", "SEEN", `Cancel ${when} | ${end} | ${early ? `result line '${early}'` : "no result line"}`);
}

async function ownPage() {
  currentStep = "buttons-own";
  await login(user, userPass);
  await openUser(user, false);
  row("buttons-own", "SEEN", await seen());
}

async function reenablePage() {
  currentStep = "reenable-page";
  await login("admin", adminPass);
  await openUser(idle, true);
  const modal = `#reenableModal${idle}`;
  await waitFor(`!!document.getElementById("reenable-user")`, "#reenable-user");
  await evalValue(`document.getElementById("reenable-user").click()`);
  await waitFor(`!!document.querySelector(${JSON.stringify(modal)})?.classList.contains("show")`, `${modal} shown`);
  await clickWithin(modal, "Yes, re-enable");
  const reenabled = await waitResult();
  row("reenable-page", "SEEN", `${reenabled} | ${await gone("sign-in-inactive", "reenable-user")}`);
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
  if (mode === "admin" && locked && fresh) await adminPage();
  else if (mode === "own" && user) await ownPage();
  else if (mode === "reenable" && idle) await reenablePage();
  else throw fail("BROWSER_MODE", `${mode || "unset"} or its users unset`);
} catch (err) {
  failed = true;
  row(currentStep || "mode", "FAIL", `${err.selector || "unknown"} ${err.message || ""}`);
  try {
    const shot = await send("Page.captureScreenshot", { format: "png" });
    await writeFile(`${outDir}/actions-${currentStep || "mode"}.png`, Buffer.from(shot.data, "base64"));
  } catch {
    // A failed shot still leaves the row.
  }
  await writeFile(`${outDir}/actions-console-${currentStep || "mode"}.txt`, consoleLines.join("\n"));
} finally {
  if (chrome && !chrome.killed) chrome.kill("SIGTERM");
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
}
process.exit(failed ? 1 : 0);
