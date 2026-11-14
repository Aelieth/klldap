// Drives the gate's own server through the Chromium baked into the Playwright image.
// Node's built-in WebSocket speaks CDP. Nothing is installed here.

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";

const outDir = process.env.BROWSER_OUT || "/out";
const mode = process.env.BROWSER_MODE;
const base = process.env.BROWSER_URL;
const userId = process.env.BROWSER_USER;
const adminPass = process.env.BROWSER_ADMIN_PASS || "";
const firstPass = process.env.BROWSER_PASS || "";
const newPass = process.env.BROWSER_NEW_PASS || "";
const secrets = [adminPass, firstPass, newPass].filter((s) => s.length > 0);
const WAIT_MS = 30000;

const consoleLines = [];
let chrome;
let ws;
let nextId = 0;
const pending = new Map();

function say(line) {
  process.stdout.write(`${line}\n`);
}

function redact(text) {
  let out = String(text ?? "");
  for (const secret of secrets) out = out.split(secret).join("[redacted]");
  return out;
}

function clipAlert(text) {
  const clean = redact(text).replace(/\s+/g, " ").trim();
  return clean.length > 200 ? clean.slice(0, 200) : clean;
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

function onMessage(raw) {
  const msg = JSON.parse(raw.data);
  if (msg.id && pending.has(msg.id)) {
    const waiter = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) waiter.reject(fail(msg.method || "cdp", msg.error.message));
    else waiter.resolve(msg.result);
    return;
  }
  if (msg.method === "Runtime.consoleAPICalled") {
    const args = (msg.params.args || [])
      .map((arg) => arg.value ?? arg.description ?? arg.type)
      .join(" ");
    consoleLines.push(redact(args));
  } else if (msg.method === "Runtime.exceptionThrown") {
    consoleLines.push(redact(msg.params.exceptionDetails?.text || "exception"));
  }
}

async function evalValue(expression) {
  const result = await send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw fail("evaluate", result.exceptionDetails.text || "evaluate failed");
  }
  return result.result?.value;
}

async function waitFor(expression, selector, timeoutMs = WAIT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await evalValue(expression)) return;
    } catch (err) {
      if (err.finding) throw err;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  let raw = "";
  try {
    raw = await evalValue(
      `document.querySelector(".alert-danger,.alert-warning")?.textContent || ""`,
    );
  } catch {
    raw = "";
  }
  const alert = clipAlert(raw);
  if (/secure context|crypto\.subtle|insecure origin/i.test(alert)) {
    const err = finding(alert);
    err.alert = alert;
    throw err;
  }
  const err = fail(selector);
  err.alert = alert;
  throw err;
}

function finding(text) {
  const err = fail("secure-context", text);
  err.finding = true;
  return err;
}

async function fill(selector, value) {
  await waitFor(
    `!!document.querySelector(${JSON.stringify(selector)})`,
    selector,
  );
  try {
    await evalValue(`(() => {
      const el = document.querySelector(${JSON.stringify(selector)});
      const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
      proto.set.call(el, ${JSON.stringify(value)});
      el.dispatchEvent(new InputEvent("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    })()`);
  } catch (err) {
    if (err.finding) throw err;
    throw fail(selector);
  }
}

async function clickButton(label) {
  const selector = `button ${label}`;
  await waitFor(
    `(() => {
      const btn = [...document.querySelectorAll("button")].find((b) =>
        b.textContent.includes(${JSON.stringify(label)}) && !b.disabled);
      return !!btn;
    })()`,
    selector,
  );
  const clicked = await evalValue(`(() => {
    const btn = [...document.querySelectorAll("button")].find((b) =>
      b.textContent.includes(${JSON.stringify(label)}) && !b.disabled);
    if (!btn) return false;
    btn.click();
    return true;
  })()`);
  if (!clicked) throw fail(selector);
}

async function goto(path) {
  await send("Page.navigate", { url: `${base}${path}` });
  await waitFor(
    `location.pathname === ${JSON.stringify(path)}`,
    `path ${path}`,
  );
}

async function assertKerberosOn() {
  const selector = "Kerberos Sync On";
  const rowExpr = `[...document.querySelectorAll(".row")].find((r) => r.textContent.includes("Kerberos Sync"))`;
  await waitFor(
    `(() => {
      const row = ${rowExpr};
      return !!row && [...row.querySelectorAll("button")].some((b) => b.textContent.trim() === "On");
    })()`,
    selector,
  );
  const on = await evalValue(`(() => {
    const row = ${rowExpr};
    const button = [...row.querySelectorAll("button")].find((b) => b.textContent.trim() === "On");
    return button.classList.contains("active");
  })()`);
  if (!on) {
    await evalValue(`(() => {
      const row = ${rowExpr};
      [...row.querySelectorAll("button")].find((b) => b.textContent.trim() === "On").click();
      return true;
    })()`);
    await waitFor(
      `(() => {
        const row = ${rowExpr};
        const button = [...row.querySelectorAll("button")].find((b) => b.textContent.trim() === "On");
        return button.classList.contains("active");
      })()`,
      selector,
    );
  }
}

async function screenshot(step) {
  try {
    const shot = await send("Page.captureScreenshot", { format: "png" });
    await writeFile(`${outDir}/${step}.png`, Buffer.from(shot.data, "base64"));
  } catch {
    // The row still names the selector when the screenshot itself fails.
  }
}

async function writeConsole(step) {
  const body = consoleLines.map((line) => redact(line)).join("\n");
  await writeFile(`${outDir}/console-${step}.txt`, body);
}

async function connect() {
  const home = process.env.HOME || "/tmp/home";
  await mkdir(home, { recursive: true });
  await mkdir("/tmp/chrome-user", { recursive: true });
  const bin = chromeBin();
  chrome = spawn(
    bin,
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
  chrome.stderr.on("data", (chunk) => {
    consoleLines.push(redact(chunk.toString()));
  });
  const deadline = Date.now() + WAIT_MS;
  let page;
  while (Date.now() < deadline) {
    try {
      const res = await fetch("http://127.0.0.1:9222/json/list");
      const list = await res.json();
      page = list.find((target) => target.type === "page" && target.webSocketDebuggerUrl);
      if (page) break;
    } catch {
      // The port is not up yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!page) throw fail("chrome", "debug port");
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", () => reject(fail("chrome", "debug socket")), {
      once: true,
    });
  });
  ws.addEventListener("message", onMessage);
  await send("Page.enable");
  await send("Runtime.enable");
}

async function recordContext() {
  const info = await evalValue(`({ secure: window.isSecureContext, url: location.href })`);
  say(`CONTEXT secure=${info.secure} url=${info.url}`);
}

let currentStep = mode === "change" ? "user-login" : "admin-login";

async function login(who, password, row) {
  currentStep = row;
  await goto("/login");
  await recordContext();
  await waitFor(`!!document.querySelector("#username")`, "#username");
  await fill("#username", who);
  await fill("#password", password);
  await clickButton("Login");
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes("Logout"))`,
    "button Logout",
  );
  say(`ROW ${row} PASS`);
}

async function createUser() {
  currentStep = "create";
  await goto("/users/create");
  await waitFor(`!!document.querySelector("input[name=mail]")`, "input[name=mail]");
  await fill("#username", userId);
  await fill("input[name=mail]", `${userId}@gate.test`);
  await fill("#password", firstPass);
  await fill("#confirm_password", firstPass);
  await assertKerberosOn();
  await clickButton("Submit");
  await waitFor(`location.pathname === "/users"`, "path /users");
  say("ROW create PASS");
}

async function changePassword() {
  currentStep = "change";
  await goto(`/user/${userId}/password`);
  await waitFor(`!!document.querySelector("#old_password")`, "#old_password");
  await fill("#old_password", firstPass);
  await fill("#password", newPass);
  await fill("#confirm_password", newPass);
  await clickButton("Change Password");
  await waitFor(
    `location.pathname === ${JSON.stringify(`/user/${userId}`)}`,
    `path /user/${userId}`,
  );
  say("ROW change PASS");
}

async function main() {
  await connect();
  if (mode === "create") {
    await login("admin", adminPass, "admin-login");
    await createUser();
  } else if (mode === "change") {
    await login(userId, firstPass, "user-login");
    await changePassword();
  } else {
    throw fail("BROWSER_MODE", mode || "unset");
  }
}

let failed = false;
try {
  await main();
} catch (err) {
  failed = true;
  if (err.finding) say(`FINDING ${redact(err.message)}`);
  const alert = err.alert ? ` ${err.alert}` : "";
  say(`ROW ${currentStep} FAIL ${err.selector || "unknown"}${alert}`);
  await screenshot(currentStep);
  await writeConsole(currentStep);
} finally {
  if (chrome && !chrome.killed) chrome.kill("SIGTERM");
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
}
process.exit(failed ? 1 : 0);
