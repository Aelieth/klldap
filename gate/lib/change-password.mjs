// Change-password page. Phase 94's driver is the model. The phase classifies the row.

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";

const outDir = process.env.BROWSER_OUT || "/out";
const base = process.env.BROWSER_URL;
const mode = process.env.BROWSER_MODE;
const who = process.env.BROWSER_USER;
const adminPass = process.env.BROWSER_ADMIN_PASS || "";
const typed = process.env.BROWSER_PASS || "";
const secrets = [adminPass, typed].filter((s) => s.length > 0);
const WAIT_MS = 30000;

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
    if (msg.error) waiter.reject(fail("cdp", msg.error.message));
    else waiter.resolve(msg.result);
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

async function waitFor(expression, selector) {
  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    try {
      if (await evalValue(expression)) return;
    } catch {
      // The page is still loading.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw fail(selector);
}

async function goto(path) {
  await send("Page.navigate", { url: `${base}${path}` });
  await waitFor(`location.pathname === ${JSON.stringify(path)}`, `path ${path}`);
}

async function clickButton(label) {
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes(${JSON.stringify(label)}) && !b.disabled)`,
    `button ${label}`,
  );
  const clicked = await evalValue(`(() => {
    const btn = [...document.querySelectorAll("button")].find((b) =>
      b.textContent.includes(${JSON.stringify(label)}) && !b.disabled);
    if (!btn) return false;
    btn.click();
    return true;
  })()`);
  if (!clicked) throw fail(`button ${label}`);
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
    ws.addEventListener("error", () => reject(fail("chrome", "debug socket")), { once: true });
  });
  ws.addEventListener("message", onMessage);
  await send("Page.enable");
  await send("Runtime.enable");
}

async function login() {
  await goto("/login");
  await waitFor(`!!document.querySelector("#username")`, "#username");
  await evalValue(`(() => {
    const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
    for (const [sel, value] of [["#username", "admin"], ["#password", ${JSON.stringify(adminPass)}]]) {
      const el = document.querySelector(sel);
      proto.set.call(el, value);
      el.dispatchEvent(new InputEvent("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    }
    return true;
  })()`);
  await clickButton("Login");
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes("Logout"))`,
    "button Logout",
  );
}

async function fillNew(value) {
  await waitFor(
    `document.querySelectorAll('input[autocomplete="new-password"]').length >= 2`,
    "new password",
  );
  const ok = await evalValue(`(() => {
    const els = [...document.querySelectorAll('input[autocomplete="new-password"]')];
    const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
    for (const el of els) {
      proto.set.call(el, ${JSON.stringify(value)});
      el.dispatchEvent(new InputEvent("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    }
    return els.length >= 2 && els.every((el) => el.value === ${JSON.stringify(value)});
  })()`);
  if (!ok) throw fail("new password", "the fields did not take the value");
}

async function openChange() {
  await goto(`/user/${who}/password`);
  await waitFor(
    `[...document.querySelectorAll("h5")].some((h) => h.textContent.includes("Change Password"))`,
    "Change Password",
  );
}

let failed = false;
try {
  await connect();
  await login();
  await openChange();
  await fillNew(typed);
  await clickButton("Change Password");
  if (mode === "web-one") {
    await waitFor(
      `document.body.textContent.includes("Invalid password. Min length: 8")`,
      "Invalid password. Min length: 8",
    );
    const stayed = await evalValue(`location.pathname.endsWith("/password")`);
    if (!stayed) throw fail("path", "left the change page");
    say("PAGE web-one Invalid password. Min length: 8");
  } else if (mode === "web-pol") {
    await waitFor(
      `(() => {
        const alert = document.querySelector(".alert-danger");
        return !!alert && alert.textContent.includes("Failed to set new password")
          && alert.textContent.includes("min_length 12");
      })()`,
      "min_length 12",
    );
    const text = await evalValue(`document.querySelector(".alert-danger").textContent.replace(/\\s+/g, " ").trim()`);
    const stayed = await evalValue(`location.pathname.endsWith("/password")`);
    if (!stayed) throw fail("path", "the page treated the sync refusal as success");
    say(`PAGE web-pol ${redact(text)}`);
  } else {
    throw fail("BROWSER_MODE", mode || "unset");
  }
} catch (err) {
  failed = true;
  const row = mode === "web-pol" ? "web-pol" : "web-one";
  say(`ROW ${row} FAIL ${err.selector || "unknown"} ${redact(err.message || "")}`);
  try {
    const shot = await send("Page.captureScreenshot", { format: "png" });
    await writeFile(`${outDir}/${row}.png`, Buffer.from(shot.data, "base64"));
  } catch {
    // The row still names the selector.
  }
} finally {
  if (chrome && !chrome.killed) chrome.kill("SIGTERM");
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
}
process.exit(failed ? 1 : 0);
