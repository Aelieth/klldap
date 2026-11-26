// Drives the gate's own server through the Chromium baked into the Playwright image.
// Node's built-in WebSocket speaks CDP. Nothing is installed here. BROWSER_MODE mfa drives the
// two-factor pages as BROWSER_USER and prints, per row, what the page sent (WIRE lines);
// ou-mfa and ou-main sign in BROWSER_USER and BROWSER_CODE_USER under their OUs' enable-mfa.

import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { networkInterfaces } from "node:os";

const outDir = process.env.BROWSER_OUT || "/out";
const mode = process.env.BROWSER_MODE;
const base = process.env.BROWSER_URL;
const userId = process.env.BROWSER_USER;
const adminPass = process.env.BROWSER_ADMIN_PASS || "";
const firstPass = process.env.BROWSER_PASS || "";
const newPass = process.env.BROWSER_NEW_PASS || "";
const codeUser = process.env.BROWSER_CODE_USER || "";
const totpSecret = process.env.BROWSER_TOTP_SECRET || "";
const secrets = [adminPass, firstPass, newPass, totpSecret].filter((s) => s.length > 0);
const userSecrets = [firstPass, newPass].filter((s) => s.length > 0);
const WAIT_MS = 30000;
const LOGIN_START = "/auth/opaque/login/start";
const LOGIN_FINISH = "/auth/opaque/login/finish";
const LOGOUT_VISIBLE = `[...document.querySelectorAll("button")].some((b) => b.textContent.includes("Logout"))`;
const wire = { requests: [], finishStatuses: [], consoleLeaks: 0 };
const usedCodes = new Set();

// The password as a request or a print could carry it: plain, base64, hex, URL- and
// JSON-escaped, and as the byte array serde writes.
function encodings(secret) {
  const bytes = Buffer.from(secret, "utf8");
  return [
    secret,
    bytes.toString("base64").replace(/=+$/, ""),
    bytes.toString("base64url"),
    bytes.toString("hex"),
    bytes.toString("hex").toUpperCase(),
    encodeURIComponent(secret),
    JSON.stringify(secret).slice(1, -1),
    JSON.stringify([...bytes]),
  ];
}
const needles = [...new Set(userSecrets.flatMap(encodings))];

function carries(text) {
  const raw = String(text ?? "");
  return needles.some((needle) => raw.includes(needle));
}

// Checked before it is redacted: a print of the password fails its row.
function noteConsole(text) {
  if (carries(text)) wire.consoleLeaks += 1;
  consoleLines.push(redact(text));
}

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
    noteConsole(args);
  } else if (msg.method === "Runtime.exceptionThrown") {
    noteConsole(msg.params.exceptionDetails?.text || "exception");
  } else if (msg.method === "Network.requestWillBeSent") {
    const request = msg.params.request || {};
    wire.requests.push({ url: request.url || "", body: postBody(request) });
  } else if (msg.method === "Network.responseReceived") {
    const response = msg.params.response || {};
    if ((response.url || "").includes(LOGIN_FINISH)) wire.finishStatuses.push(String(response.status));
  }
}

function postBody(request) {
  if (request.postDataEntries?.length) {
    return request.postDataEntries
      .map((entry) => Buffer.from(entry.bytes || "", "base64").toString("utf8"))
      .join("");
  }
  return request.postData || "";
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
    noteConsole(chunk.toString());
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
  const captured = ["mfa", "pages-one", "change", "code-retry", "ou-mfa", "ou-main"];
  if (captured.includes(mode)) {
    await send("Network.enable", { maxPostDataSize: 65536 });
  }
}

async function recordContext() {
  const info = await evalValue(`({ secure: window.isSecureContext, url: location.href })`);
  say(`CONTEXT secure=${info.secure} url=${info.url}`);
}

const firstSteps = {
  change: "user-login",
  mfa: "mfa-login",
  "code-retry": "retry-enrol",
  "ou-mfa": "ou-pending",
  "ou-main": "ou-main-always",
};
let currentStep = firstSteps[mode] || "admin-login";

// From a landing page the app comes back to it after the login, with the key its sign-in bound.
async function login(who, password, row, landing) {
  currentStep = row;
  if (landing) await send("Page.navigate", { url: `${base}${landing}` });
  else await goto("/login");
  await waitFor(`location.pathname === "/login" && !!document.querySelector("#username")`, "#username");
  await recordContext();
  await fill("#username", who);
  await fill("#password", password);
  await clickButton("Login");
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes("Logout"))`,
    "button Logout",
  );
  if (landing) await waitFor(`location.pathname === ${JSON.stringify(landing)}`, `path ${landing}`);
  say(`ROW ${row} PASS`);
}

async function createUser() {
  currentStep = "create";
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
  beginRow("change");
  await twoSubmits("Change Password");
  await waitFor(
    `location.pathname === ${JSON.stringify(`/user/${userId}`)}`,
    `path /user/${userId}`,
  );
  await endRow("change");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitText(text) {
  await waitFor(`document.body.innerText.includes(${JSON.stringify(text)})`, `text ${text}`);
}

function base32Bytes(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of text.replace(/=+$/, "")) {
    const index = alphabet.indexOf(ch);
    if (index < 0) throw fail("secret", "the secret is not base32");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}

// RFC 6238 as the server computes it: SHA-1, six digits, 30-second steps.
function totp(secret, offset) {
  const step = Math.floor(Date.now() / 30000) + offset;
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", base32Bytes(secret)).update(counter).digest();
  const at = digest[19] & 0x0f;
  return String((digest.readUInt32BE(at) & 0x7fffffff) % 1000000).padStart(6, "0");
}

async function freshCode(secret) {
  const deadline = Date.now() + 100000;
  while (Date.now() < deadline) {
    // Never a past step: it can be two steps old by the time the server checks it.
    for (const offset of [0, 1]) {
      const code = totp(secret, offset);
      if (!usedCodes.has(`${secret}:${code}`)) {
        usedCodes.add(`${secret}:${code}`);
        return code;
      }
    }
    await sleep(1000);
  }
  throw fail("code", "no unused code in reach");
}

function wrongCode(secret) {
  const valid = [-1, 0, 1].map((offset) => totp(secret, offset));
  for (let n = 0; ; n++) {
    const code = String(n).padStart(6, "0");
    if (!valid.includes(code)) return code;
  }
}

async function readSecret() {
  await waitFor(`!!document.querySelector('img[alt="TOTP QR code"]')`, "TOTP QR code");
  const text = await evalValue(
    `[...document.querySelectorAll("p.text-center code")].map((c) => c.textContent).join("")`,
  );
  const secret = String(text || "").replace(/\s+/g, "");
  if (!/^[A-Z2-7]+=*$/.test(secret)) throw fail("secret", "no base32 secret on the page");
  secrets.push(secret);
  return secret;
}

async function typeCredentials(who, password) {
  await waitFor(`!!document.querySelector("#username")`, "#username");
  await fill("#username", who);
  await fill("#password", password);
  await clickButton("Login");
}

function beginRow(row) {
  currentStep = row;
  wire.requests = [];
  wire.finishStatuses = [];
  wire.consoleLeaks = 0;
}

// Two submits in one task. Yew renders the first at once and disables the button, so the
// second goes through it enabled again: only the page's own in-flight guard can stop it.
async function twoSubmits(label) {
  const find = `[...document.querySelectorAll("button")].find((b) =>
    b.textContent.includes(${JSON.stringify(label)}) && !b.disabled)`;
  await waitFor(`!!${find}`, `button ${label}`);
  const clicked = await evalValue(`(() => {
    const btn = ${find};
    if (!btn) return false;
    btn.click();
    btn.disabled = false;
    btn.click();
    return true;
  })()`);
  if (!clicked) throw fail(`button ${label}`);
  await sleep(100);
}

// What the row sent: the login starts and finishes, what each finish asked for, the finish
// statuses, whether any request carried the user's password, and whether the page kept it.
async function endRow(row) {
  await sleep(500);
  const finishes = wire.requests.filter((r) => r.url.includes(LOGIN_FINISH));
  const bodies = finishes.map((r) => {
    try {
      return JSON.parse(r.body);
    } catch {
      return {};
    }
  });
  const starts = wire.requests.filter((r) => r.url.includes(LOGIN_START)).length;
  const sent = wire.requests.some((r) => carries(r.url) || carries(r.body));
  const stored = await evalValue(`(() => {
    const kept = JSON.stringify(Object.entries(localStorage)) +
      JSON.stringify(Object.entries(sessionStorage)) + document.cookie;
    return ${JSON.stringify(userSecrets)}.some((s) => kept.includes(s));
  })()`);
  const count = (test) => bodies.filter(test).length;
  say(
    [
      `WIRE ${row}`,
      `starts=${starts}`,
      `finishes=${finishes.length}`,
      `sessionless=${count((b) => b.session === false)}`,
      `proof-asked=${count((b) => b.enrollmentProof === true)}`,
      `codes=${count((b) => typeof b.totp_code === "string")}`,
      `statuses=${wire.finishStatuses.join("/") || "none"}`,
      `password-sent=${sent ? "yes" : "no"}`,
      `stored=${stored ? "yes" : "no"}`,
      `console-leak=${wire.consoleLeaks > 0 ? "yes" : "no"}`,
    ].join(" "),
  );
  say(`ROW ${row} PASS`);
}

async function mfaPages() {
  const own = `/user/${userId}`;
  beginRow("mfa-login");
  await goto("/login");
  await recordContext();
  await waitFor(`!!document.querySelector("#username")`, "#username");
  await fill("#username", userId);
  await fill("#password", firstPass);
  await twoSubmits("Login");
  await waitFor(LOGOUT_VISIBLE, "button Logout");
  await endRow("mfa-login");

  beginRow("mfa-enrol");
  await goto(`${own}/mfa`);
  await fill("#current_password", firstPass);
  await twoSubmits("Continue");
  const first = await readSecret();
  await fill("#combined", `${firstPass}:${await freshCode(first)}`);
  await twoSubmits("Enable two-factor");
  await waitText("Two-factor authentication is enabled.");
  await endRow("mfa-enrol");

  await clickButton("Logout");
  beginRow("mfa-old-form");
  await typeCredentials(userId, `${firstPass}:${totp(first, 0)}`);
  await waitText("the code is asked in the next step");
  await waitText("Invalid username or password");
  await endRow("mfa-old-form");

  beginRow("mfa-wrong-code");
  await typeCredentials(userId, firstPass);
  await waitFor(`!!document.querySelector("#totp_code")`, "#totp_code");
  await fill("#totp_code", wrongCode(first));
  await clickButton("Verify");
  await waitText("Invalid code");
  await waitFor(`!!document.querySelector("#totp_code")`, "#totp_code");
  await endRow("mfa-wrong-code");

  beginRow("mfa-signin");
  await fill("#totp_code", await freshCode(first));
  await twoSubmits("Verify");
  await waitFor(LOGOUT_VISIBLE, "button Logout");
  await endRow("mfa-signin");

  beginRow("mfa-replace");
  await goto(`${own}/mfa`);
  await fill("#current_code", await freshCode(first));
  await clickButton("Continue");
  const second = await readSecret();
  await fill("#combined", `${firstPass}:${await freshCode(second)}`);
  await clickButton("Enable two-factor");
  await waitText("Two-factor authentication is enabled.");
  await endRow("mfa-replace");

  beginRow("mfa-change");
  await goto(`${own}/password`);
  await fill("#old_password", firstPass);
  await fill("#password", newPass);
  await fill("#confirm_password", newPass);
  await twoSubmits("Change Password");
  await waitFor(`location.pathname === ${JSON.stringify(own)}`, `path ${own}`);
  await endRow("mfa-change");

  beginRow("mfa-reset");
  await goto(`${own}/mfa/reset`);
  await fill("#combined", `${newPass}:${await freshCode(second)}`);
  await twoSubmits("Reset two-factor");
  await waitFor(`location.pathname === ${JSON.stringify(own)}`, `path ${own}`);
  await endRow("mfa-reset");
}

// The code step for BROWSER_CODE_USER, with the step after the one its enrolment spent.
async function codeStep(row) {
  beginRow(row);
  await typeCredentials(codeUser, firstPass);
  await waitFor(`!!document.querySelector("#totp_code")`, "#totp_code");
  await fill("#totp_code", totp(totpSecret, 1));
  await clickButton("Verify");
  await waitFor(LOGOUT_VISIBLE, "button Logout");
  await endRow(row);
}

// No server-wide value: the OU's always lets the unenrolled BROWSER_USER in only to enroll, and
// the OU's enabled asks the enrolled BROWSER_CODE_USER for the code.
async function ouMfa() {
  const enrol = `/user/${userId}/mfa`;
  beginRow("ou-pending");
  await goto("/login");
  await recordContext();
  await typeCredentials(userId, firstPass);
  await waitFor(`location.pathname === ${JSON.stringify(enrol)}`, `path ${enrol}`);
  await waitFor(`!!document.querySelector("#current_password")`, "#current_password");
  await endRow("ou-pending");

  currentStep = "ou-confined";
  await goto(`/user/${userId}`);
  await waitFor(`location.pathname === ${JSON.stringify(enrol)}`, `path ${enrol} again`);
  say("ROW ou-confined PASS");

  await clickButton("Logout");
  await codeStep("ou-code");
}

// The server's explicit enabled overrides the OUs: under the OU's always the unenrolled
// BROWSER_USER signs in to their own page, and under the OU's off the enrolled one gets the code.
async function ouMain() {
  const own = `/user/${userId}`;
  beginRow("ou-main-always");
  await goto("/login");
  await recordContext();
  await typeCredentials(userId, firstPass);
  await waitFor(LOGOUT_VISIBLE, "button Logout");
  await waitFor(`location.pathname === ${JSON.stringify(own)}`, `path ${own}`);
  await endRow("ou-main-always");

  await clickButton("Logout");
  await codeStep("ou-main-off");
}

// A refused user at both login doors, from this container's own address.
async function refused() {
  currentStep = "refused-web";
  await goto("/login");
  await waitFor(`!!document.querySelector("#username")`, "#username");
  await fill("#username", userId);
  await fill("#password", firstPass);
  await clickButton("Login");
  await waitFor(
    `document.body.innerText.includes("Invalid username or password")`,
    "text Invalid username or password",
  );
  say("ROW refused-web PASS");
  currentStep = "refused-simple";
  const res = await fetch(`${base}/auth/simple/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: userId, password: firstPass }),
  });
  say(`SIMPLE ${res.status}`);
  const own = Object.values(networkInterfaces())
    .flat()
    .filter((a) => a && (a.family === "IPv4" || a.family === 4) && !a.internal)
    .map((a) => a.address);
  say(`ADDR ${own.join(",") || "none"}`);
}

// Each page with the right password, as a user at threshold 1: every start is finished.
// A wrong code, then the right one, on the code step. Between them the gate reads the stored
// count: the page waits for its go file in /out.
async function codeRetry() {
  const own = `/user/${userId}`;
  beginRow("retry-enrol");
  await goto("/login");
  await typeCredentials(userId, firstPass);
  await waitFor(LOGOUT_VISIBLE, "button Logout");
  await goto(`${own}/mfa`);
  await fill("#current_password", firstPass);
  await clickButton("Continue");
  const secret = await readSecret();
  await fill("#combined", `${firstPass}:${await freshCode(secret)}`);
  await clickButton("Enable two-factor");
  await waitText("Two-factor authentication is enabled.");
  await endRow("retry-enrol");

  await clickButton("Logout");
  beginRow("retry-wrong");
  await typeCredentials(userId, firstPass);
  await waitFor(`!!document.querySelector("#totp_code")`, "#totp_code");
  await fill("#totp_code", wrongCode(secret));
  await clickButton("Verify");
  await waitText("Invalid code");
  await waitFor(`!!document.querySelector("#totp_code")`, "#totp_code");
  await endRow("retry-wrong");

  const go = `${outDir}/code-retry.go`;
  const deadline = Date.now() + 60000;
  while (!existsSync(go)) {
    if (Date.now() > deadline) throw fail("go", "the gate did not read the count");
    await sleep(250);
  }
  beginRow("retry-right");
  await fill("#totp_code", await freshCode(secret));
  await clickButton("Verify");
  await waitFor(LOGOUT_VISIBLE, "button Logout");
  await endRow("retry-right");
}

async function pagesAtOne() {
  const own = `/user/${userId}`;
  beginRow("one-login");
  await goto("/login");
  await typeCredentials(userId, firstPass);
  await waitFor(LOGOUT_VISIBLE, "button Logout");
  await endRow("one-login");

  beginRow("one-enrol");
  await goto(`${own}/mfa`);
  await fill("#current_password", firstPass);
  await clickButton("Continue");
  const secret = await readSecret();
  await fill("#combined", `${firstPass}:${await freshCode(secret)}`);
  await clickButton("Enable two-factor");
  await waitText("Two-factor authentication is enabled.");
  await endRow("one-enrol");

  await clickButton("Logout");
  beginRow("one-signin");
  await typeCredentials(userId, firstPass);
  await waitFor(`!!document.querySelector("#totp_code")`, "#totp_code");
  await fill("#totp_code", await freshCode(secret));
  await clickButton("Verify");
  await waitFor(LOGOUT_VISIBLE, "button Logout");
  await endRow("one-signin");

  beginRow("one-change");
  await goto(`${own}/password`);
  await fill("#old_password", firstPass);
  await fill("#password", newPass);
  await fill("#confirm_password", newPass);
  await clickButton("Change Password");
  await waitFor(`location.pathname === ${JSON.stringify(own)}`, `path ${own}`);
  await endRow("one-change");

  beginRow("one-reset");
  await goto(`${own}/mfa/reset`);
  await fill("#combined", `${newPass}:${await freshCode(secret)}`);
  await clickButton("Reset two-factor");
  await waitFor(`location.pathname === ${JSON.stringify(own)}`, `path ${own}`);
  await endRow("one-reset");
}

async function main() {
  await connect();
  if (mode === "create") {
    await login("admin", adminPass, "admin-login", "/users/create");
    await createUser();
  } else if (mode === "change") {
    await login(userId, firstPass, "user-login");
    await changePassword();
  } else if (mode === "mfa") {
    await mfaPages();
  } else if (mode === "refused") {
    await refused();
  } else if (mode === "login") {
    await login(userId, firstPass, "user-login");
  } else if (mode === "code-retry") {
    await codeRetry();
  } else if (mode === "pages-one") {
    await pagesAtOne();
  } else if (mode === "ou-mfa") {
    await ouMfa();
  } else if (mode === "ou-main") {
    await ouMain();
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
