// What a password page sends, run as the admin: the start key, the finish envelope and status, and
// GraphQL's syncKerberosPassword or createUser. BROWSER_FINISH_MODE add|swap puts
// BROWSER_FINISH_ENVELOPE into the finish body. Values are never printed.

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";

const outDir = process.env.BROWSER_OUT || "/out";
const base = process.env.BROWSER_URL;
const pageKind = process.env.BROWSER_PAGE || "change";
const who = process.env.BROWSER_USER;
const mail = process.env.BROWSER_MAIL || "";
const tag = process.env.BROWSER_TAG || who;
const adminPass = process.env.BROWSER_ADMIN_PASS || "";
const typed = process.env.BROWSER_PASS || "";
const finishMode = process.env.BROWSER_FINISH_MODE || "";
const finishEnvelope = process.env.BROWSER_FINISH_ENVELOPE || "";
const secrets = [adminPass, typed, finishEnvelope].filter((s) => s.length > 0);
const WAIT_MS = 30000;
const START = "/auth/opaque/register/start";
const FINISH = "/auth/opaque/register/finish";

let chrome;
let ws;
let nextId = 0;
const pending = new Map();
const wire = {
  startKey: "none",
  finishEnvelope: "none",
  rewrite: "none",
  finishStatus: "none",
  graphqlSeal: "no",
  createSent: "no",
};
const startIds = new Set();

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

function postBody(request) {
  if (request?.postDataEntries?.length) {
    return request.postDataEntries
      .map((entry) => Buffer.from(entry.bytes || "", "base64").toString("utf8"))
      .join("");
  }
  return request?.postData || "";
}

function hasEnvelope(body) {
  return body.includes('"kerberos_password_envelope"') ? "yes" : "no";
}

function rewriteFinish(params) {
  const body = postBody(params.request);
  wire.finishEnvelope = hasEnvelope(body);
  let out = body;
  try {
    const json = JSON.parse(body);
    wire.rewrite = "kerberos_password_envelope" in json ? "swapped" : "added";
    json.kerberos_password_envelope = finishEnvelope;
    out = JSON.stringify(json);
  } catch {
    wire.rewrite = "unparsed";
  }
  send("Fetch.continueRequest", {
    requestId: params.requestId,
    postData: Buffer.from(out, "utf8").toString("base64"),
  }).catch(() => {
    wire.rewrite = "not-sent";
  });
}

function onEvent(msg) {
  const params = msg.params || {};
  if (msg.method === "Fetch.requestPaused") {
    rewriteFinish(params);
    return;
  }
  if (msg.method === "Network.requestWillBeSent") {
    const url = params.request?.url || "";
    const body = postBody(params.request);
    if (url.includes(START)) startIds.add(params.requestId);
    if (url.includes(FINISH) && !finishMode) wire.finishEnvelope = hasEnvelope(body);
    if (url.includes("/api/graphql") && body.includes("syncKerberosPassword")) wire.graphqlSeal = "yes";
    if (url.includes("/api/graphql") && body.includes("createUser")) wire.createSent = "yes";
  }
  if (msg.method === "Network.responseReceived" && (params.response?.url || "").includes(FINISH)) {
    wire.finishStatus = String(params.response.status);
  }
  if (msg.method === "Network.loadingFinished" && startIds.has(params.requestId)) {
    send("Network.getResponseBody", { requestId: params.requestId })
      .then((res) => {
        wire.startKey = (res.body || "").includes('"kerberos_envelope_key"') ? "yes" : "no";
      })
      .catch(() => {
        wire.startKey = "unread";
      });
  }
}

function onMessage(raw) {
  const msg = JSON.parse(raw.data);
  if (msg.method) onEvent(msg);
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
  await send("Network.enable", { maxPostDataSize: 65536 });
  if (finishMode) {
    await send("Fetch.enable", { patterns: [{ urlPattern: `*${FINISH}*`, requestStage: "Request" }] });
  }
}

async function setValues(pairs) {
  return evalValue(`(() => {
    const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
    for (const [sel, value] of ${JSON.stringify(pairs)}) {
      const el = document.querySelector(sel);
      if (!el) return false;
      proto.set.call(el, value);
      el.dispatchEvent(new InputEvent("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    }
    return true;
  })()`);
}

async function login() {
  await goto("/login");
  await waitFor(`!!document.querySelector("#username")`, "#username");
  await setValues([
    ["#username", "admin"],
    ["#password", adminPass],
  ]);
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

async function openCreate() {
  await goto("/users/create");
  await waitFor(`!!document.querySelector("#username") && !!document.querySelector('input[name="mail"]')`, "create form");
  if (!(await setValues([["#username", who], ['input[name="mail"]', mail]]))) {
    throw fail("create form", "the user name or mail field is missing");
  }
}

async function alertText() {
  return evalValue(`[...document.querySelectorAll(".alert-danger")].map((a) => a.textContent).join(" ").replace(/\\s+/g, " ").trim()`);
}

let failed = false;
try {
  await connect();
  await login();
  const leaves = pageKind === "create" ? `location.pathname === "/users"` : `!location.pathname.endsWith("/password")`;
  if (pageKind === "create") await openCreate();
  else await openChange();
  await fillNew(typed);
  await clickButton(pageKind === "create" ? "Submit" : "Change Password");
  const deadline = Date.now() + WAIT_MS;
  let page = "stayed";
  while (Date.now() < deadline) {
    if (await evalValue(leaves)) {
      page = "done";
      break;
    }
    if (await evalValue(`!!document.querySelector(".alert-danger")`)) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  await new Promise((resolve) => setTimeout(resolve, 500));
  const alert = page === "done" ? "" : await alertText();
  say(
    `WIRE start-key=${wire.startKey} finish-envelope=${wire.finishEnvelope} rewrite=${wire.rewrite} finish-status=${wire.finishStatus} graphql-seal=${wire.graphqlSeal} create-sent=${wire.createSent} page=${page}`,
  );
  if (alert) say(`ALERT ${redact(alert).slice(0, 400)}`);
} catch (err) {
  failed = true;
  say(`ROW wire FAIL ${err.selector || "unknown"} ${redact(err.message || "")}`);
  try {
    const shot = await send("Page.captureScreenshot", { format: "png" });
    await writeFile(`${outDir}/wire-${tag}.png`, Buffer.from(shot.data, "base64"));
  } catch {
    // The row still names the selector.
  }
} finally {
  if (chrome && !chrome.killed) chrome.kill("SIGTERM");
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
}
process.exit(failed ? 1 : 0);
