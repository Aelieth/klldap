// E-mail reset page, logged out. Phase 91 requests the mail and classifies the row.

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";

const outDir = process.env.BROWSER_OUT || "/out";
const base = process.env.BROWSER_URL;
const resetToken = process.env.BROWSER_RESET_TOKEN || "";
const typed = process.env.BROWSER_PASS || "";
const secrets = [resetToken, typed].filter((s) => s.length > 0);
const WAIT_MS = 30000;
const ROW = "U1.reset-page";

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

function clip(text, max) {
  const clean = redact(text).replace(/\s+/g, " ").trim();
  return clean.length > max ? clean.slice(0, max) : clean;
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

async function within(expression) {
  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    try {
      if (await evalValue(expression)) return true;
    } catch {
      // The page is still loading.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return false;
}

async function waitFor(expression, selector) {
  if (!(await within(expression))) throw fail(selector);
}

async function goto(path) {
  await send("Page.navigate", { url: `${base}${path}` });
  await waitFor(`location.pathname === ${JSON.stringify(path)}`, "path step2");
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

async function fillNew(value) {
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

async function visible() {
  const seen = await evalValue(`(() => {
    const main = document.querySelector("main") || document.body;
    const sel = ".alert-danger,.alert-warning";
    const alert = [...main.querySelectorAll(sel)].map((a) => a.textContent).join(" ");
    const copy = main.cloneNode(true);
    copy.querySelectorAll(sel).forEach((a) => a.remove());
    return { text: copy.textContent, alert };
  })()`);
  const text = clip(seen?.text, 160) || "(empty)";
  const alert = clip(seen?.alert, 200);
  return alert ? `${text}; alert: ${alert}` : text;
}

async function screenshot() {
  const shot = await send("Page.captureScreenshot", { format: "png" }).catch(() => null);
  if (shot) await writeFile(`${outDir}/reset-page.png`, Buffer.from(shot.data, "base64")).catch(() => null);
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
    ws.addEventListener("error", () => reject(fail("chrome", "debug socket")), { once: true });
  });
  ws.addEventListener("message", onMessage);
  await send("Page.enable");
  await send("Runtime.enable");
}

async function recordContext() {
  const info = await evalValue(`({ secure: window.isSecureContext, url: location.href })`);
  say(`CONTEXT secure=${info.secure} url=${redact(info.url)}`);
}

let failed = false;
try {
  if (!resetToken) throw fail("BROWSER_RESET_TOKEN", "unset");
  if (!typed) throw fail("BROWSER_PASS", "unset");
  await connect();
  await goto(`/reset-password/step2/${resetToken}`);
  await recordContext();
  const form = await within(
    `document.querySelectorAll('input[autocomplete="new-password"]').length >= 2`,
  );
  if (!form) {
    say(`PAGE noform ${await visible()}`);
    await screenshot();
  } else {
    await fillNew(typed);
    await clickButton("Submit");
    if (await within(`location.pathname === "/login"`)) {
      say("PAGE login /login");
    } else {
      say(`PAGE stayed ${await visible()}`);
      await screenshot();
    }
  }
} catch (err) {
  failed = true;
  say(`ROW ${ROW} FAIL ${redact(err.selector || "unknown")} ${redact(err.message || "")}`);
  if (ws) await screenshot();
} finally {
  const body = consoleLines.map((line) => redact(line)).join("\n");
  await writeFile(`${outDir}/console-reset-page.txt`, body).catch(() => null);
  if (chrome && !chrome.killed) chrome.kill("SIGTERM");
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
}
process.exit(failed ? 1 : 0);
