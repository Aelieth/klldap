// Policies workbench through the gate's headless browser. Phase 94's driver is the model.

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const outDir = process.env.BROWSER_OUT || "/out";
const base = process.env.BROWSER_URL;
const adminPass = process.env.BROWSER_ADMIN_PASS || "";
const plainUser = process.env.BROWSER_PLAIN_USER || "";
const plainPass = process.env.BROWSER_PLAIN_PASS || "";
const roUser = process.env.BROWSER_RO_USER || "";
const roPass = process.env.BROWSER_RO_PASS || "";
const warnUser = process.env.BROWSER_WARN_USER || "";
const warnPass = process.env.BROWSER_WARN_PASS || "";
const warnOu = process.env.BROWSER_WARN_OU || "";
const warnPolicy = process.env.BROWSER_WARN_POLICY || "";
const zone = process.env.BROWSER_ZONE || "";
const secrets = [adminPass, plainPass, roPass, warnPass].filter((s) => s.length > 0);
const WAIT_MS = 30000;
const primary = process.env.BROWSER_PRIMARY || "";
const CHILD = process.env.BROWSER_CHILD || "";
const frontName = process.env.BROWSER_FRONT || "";
const editedName = process.env.BROWSER_EDITED || "";
const otherName = process.env.BROWSER_OTHER || "";
const badIntName = process.env.BROWSER_BADINT || "";
const badHoursName = process.env.BROWSER_BADHOURS || "";
const serverWide = process.env.BROWSER_SERVER_WIDE || "";
const unenforcedKeys = (process.env.BROWSER_UNENFORCED || "")
  .split(",")
  .map((key) => key.trim())
  .filter((key) => key.length > 0);

const ITEMS = [
  ["enable-mfa", "Enable MFA", "always", "always", "select"],
  ["lockout-threshold", "Failed logins before lockout", "3", "3 tries", "number"],
  ["lockout-duration-seconds", "Lockout duration (seconds)", "120", "120 s", "number"],
  ["login-hours", "Login hours", "Mon-Fri 09:00-17:00", "Mon-Fri 09:00-17:00", "text"],
  ["allowed-networks", "Allowed networks", "10.0.0.0/8", "10.0.0.0/8", "text"],
  ["inactivity-days", "Inactivity limit (days)", "30", "30 days", "number"],
];

const consoleLines = [];
const said = new Set();
let chrome;
let ws;
let nextId = 0;
let currentStep = "admin-login";
let pagePanicked = false;
const pending = new Map();

function say(line) {
  process.stdout.write(`${line}\n`);
}

function redact(text) {
  let out = String(text ?? "");
  for (const secret of secrets) out = out.split(secret).join("[redacted]");
  return out;
}

function clip(text) {
  const clean = redact(text).replace(/\s+/g, " ").trim();
  return clean.length > 500 ? clean.slice(0, 500) : clean;
}

function fail(selector, detail) {
  const err = new Error(redact(detail || selector));
  err.selector = selector;
  return err;
}

function row(name, kind, detail) {
  said.add(name);
  const extra = detail ? ` ${clip(detail)}` : "";
  say(`ROW ${name} ${kind}${extra}`);
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
      `document.querySelector(".alert-danger,.text-danger")?.textContent || ""`,
    );
  } catch {
    raw = "";
  }
  const err = fail(selector);
  err.alert = clip(raw);
  throw err;
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
  if (!ok) throw fail(selector, value);
}

async function clickButton(label) {
  const selector = `button ${label}`;
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes(${JSON.stringify(label)}) && !b.disabled)`,
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

async function clickWithin(root, label) {
  const selector = `${root} button ${label}`;
  await waitFor(
    `(() => {
      const box = document.querySelector(${JSON.stringify(root)});
      return !!box && [...box.querySelectorAll("button")].some((b) =>
        b.textContent.includes(${JSON.stringify(label)}) && !b.disabled);
    })()`,
    selector,
  );
  const clicked = await evalValue(`(() => {
    const box = document.querySelector(${JSON.stringify(root)});
    const btn = box && [...box.querySelectorAll("button")].find((b) =>
      b.textContent.includes(${JSON.stringify(label)}) && !b.disabled);
    if (!btn) return false;
    btn.click();
    return true;
  })()`);
  if (!clicked) throw fail(selector);
}

async function goto(path) {
  await send("Page.navigate", { url: `${base}${path}` });
  await waitFor(`location.pathname === ${JSON.stringify(path)}`, `path ${path}`);
}

async function screenshot(step) {
  try {
    const shot = await send("Page.captureScreenshot", { format: "png" });
    await writeFile(`${outDir}/${step}.png`, Buffer.from(shot.data, "base64"));
  } catch {
    // A failed shot still leaves the row.
  }
}

async function writeConsole(step) {
  const body = consoleLines.map((line) => redact(line)).join("\n");
  await writeFile(`${outDir}/console-${step}.txt`, body);
}

async function login(who, password) {
  await goto("/login");
  await fill("#username", who);
  await fill("#password", password);
  await clickButton("Login");
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes("Logout"))`,
    "button Logout",
  );
}

async function logout() {
  await clickButton("Logout");
  await waitFor(`!!document.querySelector("#username")`, "#username");
}

async function dismissStatus(needle) {
  await waitFor(
    `(() => {
      const h = document.querySelector(".bg-success h5");
      return !!h && h.textContent.includes(${JSON.stringify(needle)});
    })()`,
    needle,
  );
  await evalValue(`document.querySelector(".modal.show.d-block")?.click()`);
  await waitFor(`!document.querySelector(".bg-success h5")`, "status dismissed");
}

async function selectOu(title) {
  const selector = `tree ${title}`;
  const has = `(() => [...document.querySelectorAll(".wb-tree-row")].some((r) =>
    [...r.querySelectorAll("span[title]")].some((s) => s.title === ${JSON.stringify(title)})))()`;
  await waitFor(has, selector);
  await evalValue(`(() => {
    const row = [...document.querySelectorAll(".wb-tree-row")].find((r) =>
      [...r.querySelectorAll("span[title]")].some((s) => s.title === ${JSON.stringify(title)}));
    row.click();
    return true;
  })()`);
  await waitFor(
    `(() => [...document.querySelectorAll(".wb-tree-row.wb-selected")].some((r) =>
      [...r.querySelectorAll("span[title]")].some((s) => s.title === ${JSON.stringify(title)})))()`,
    selector,
  );
}

async function controlOf(key) {
  return `document.querySelector(${JSON.stringify(`#wb-rule-${key}`)}).closest("div.border").querySelector("select, input.form-control")`;
}

async function enableRule(key) {
  const id = `#wb-rule-${key}`;
  await waitFor(`!!document.querySelector(${JSON.stringify(id)})`, id);
  const on = await evalValue(`document.querySelector(${JSON.stringify(id)}).checked`);
  if (!on) await evalValue(`document.querySelector(${JSON.stringify(id)}).click()`);
  await waitFor(`!(${await controlOf(key)}).disabled`, id);
}

async function setRule(key, kind, value) {
  await enableRule(key);
  const control = await controlOf(key);
  const proto =
    kind === "select"
      ? "HTMLSelectElement"
      : "HTMLInputElement";
  const event = kind === "select" ? "change" : "input";
  const ok = await evalValue(`(() => {
    const el = ${control};
    const desc = Object.getOwnPropertyDescriptor(window.${proto}.prototype, "value");
    desc.set.call(el, ${JSON.stringify(value)});
    el.dispatchEvent(new Event(${JSON.stringify(event)}, { bubbles: true }));
    if (${JSON.stringify(kind)} !== "select") {
      el.dispatchEvent(new InputEvent("input", { bubbles: true }));
    }
    return el.value === ${JSON.stringify(value)};
  })()`);
  if (!ok) throw fail(`#wb-rule-${key}`, value);
}

async function panelValue(label) {
  return evalValue(`(() => {
    const row = [...document.querySelectorAll("div.d-flex")].find((r) => {
      const span = [...r.children].find((el) => el.matches("span.text-truncate"));
      return span && span.textContent.trim() === ${JSON.stringify(label)};
    });
    const value = row && [...row.children].find((el) => el.tagName === "B");
    return value ? value.textContent.trim() : "";
  })()`);
}

async function waitPanel() {
  await waitFor(
    `[...document.querySelectorAll("span.text-truncate")].some((s) => s.textContent.trim() === "Enable MFA")`,
    "Enable MFA",
  );
}

async function pageValues() {
  await waitPanel();
  const parts = [];
  for (const item of ITEMS) {
    const shown = await panelValue(item[1]);
    parts.push(`${item[0]} page=${shown}`);
    if (shown !== item[3]) throw fail(item[0], parts.join("; "));
  }
  return parts.join("; ");
}

async function createPrimary() {
  await goto("/users");
  await clickButton("Create OU");
  await waitFor(
    `document.querySelector("#createOuModal")?.classList.contains("show")`,
    "#createOuModal",
  );
  await fill(
    'input[placeholder="Enter primary OU name (e.g. office)"]',
    primary,
  );
  await clickWithin("#createOuModal", "Create OU");
  await dismissStatus(`Successfully created OU: ${primary}`);
}

async function createChild() {
  await clickButton("Create OU");
  await waitFor(
    `document.querySelector("#createOuModal")?.classList.contains("show")`,
    "#createOuModal",
  );
  await evalValue(`document.querySelector("#secondary-mode").click()`);
  await waitFor(
    `[...document.querySelectorAll("#createOuModal option")].some((o) => o.value === ${JSON.stringify(primary)})`,
    "option primary",
  );
  const picked = await evalValue(`(() => {
    const sel = document.querySelector("#createOuModal select.form-select");
    sel.value = ${JSON.stringify(primary)};
    sel.dispatchEvent(new Event("change", { bubbles: true }));
    return sel.value;
  })()`);
  if (picked !== primary) throw fail("primary select", picked);
  await fill(
    'input[placeholder="Enter secondary OU name (e.g. accounting)"]',
    CHILD,
  );
  await clickWithin("#createOuModal", "Create OU");
  await dismissStatus(`Successfully created OU: ${primary}\\${CHILD}`);
}

async function openEditorAttached() {
  await openEditorOn(CHILD);
}

async function openEditorOn(ou) {
  await selectOu(ou);
  await clickButton("Attach a policy");
  await waitFor(
    `[...document.querySelectorAll("[role=button]")].some((el) => el.textContent.includes("Make a new policy and attach it here"))`,
    "Make a new policy and attach it here",
  );
  await evalValue(`(() => {
    const el = [...document.querySelectorAll("[role=button]")].find((node) =>
      node.textContent.includes("Make a new policy and attach it here"));
    el.click();
    return true;
  })()`);
  await waitFor(
    `!!document.querySelector('input[placeholder="e.g. Front Desk"]')`,
    "policy name",
  );
}

async function saveNamed(name, description) {
  await fill('input[placeholder="e.g. Front Desk"]', name);
  if (description !== undefined) {
    await fill('input[placeholder="What is this policy for?"]', description);
  }
  for (const item of ITEMS) await setRule(item[0], item[4], item[2]);
  await clickButton("Save");
  await waitFor(
    `(() => {
      const card = document.querySelector(".pol-card");
      return !!card && card.textContent.includes(${JSON.stringify(name)}) && card.textContent.includes("on this OU");
    })()`,
    name,
  );
}

async function adminLogin() {
  await login("admin", adminPass);
  row("admin-login", "PASS");
}

async function createOu() {
  await createPrimary();
  await createChild();
  row("create-ou", "PASS", `${primary} and ${primary}\\${CHILD}`);
}

async function openPolicies() {
  await goto("/policies");
  try {
    await waitFor(
      `[...document.querySelectorAll("h5")].some((h) => h.textContent.trim() === "Policies")`,
      "h5 Policies",
    );
  } catch (err) {
    let body = "";
    try {
      body = await evalValue(`document.body ? document.body.innerText : ""`);
    } catch {
      body = "";
    }
    const panicked =
      consoleLines.some((line) => line.includes("Modal node is not an element")) ||
      String(body).includes("Loading");
    if (panicked) {
      pagePanicked = true;
      row(
        "open-policies",
        "FINDING",
        "Modal node is not an element; the policies page stays on Loading",
      );
      await screenshot("open-policies");
      await writeConsole("open-policies");
      return;
    }
    throw err;
  }
  await selectOu(CHILD);
  row("open-policies", "PASS");
}

async function saveControls() {
  await openEditorAttached();
  await saveNamed(frontName, "desk hours");
  await checkNoWarning("save-controls");
  row("save-controls", "PASS", ITEMS.map((item) => `${item[0]}=${item[2]}`).join(" "));
}

// The address the server judges for this page's own session, as the page asks it.
async function clientAddress() {
  return evalValue(`fetch("/api/graphql", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "{ clientAddress }" }),
  }).then((r) => r.json()).then((b) => (b.data ? b.data.clientAddress : "<error>"))`);
}

async function noteText(selector) {
  await waitFor(`!!document.querySelector(${JSON.stringify(selector)})`, selector);
  return evalValue(`document.querySelector(${JSON.stringify(selector)}).textContent.trim()`);
}

async function zoneNote() {
  await openEditorAttached();
  const want = `judged in ${zone}`;
  const text = await noteText("#wb-note-login-hours");
  row("zone-note", text === want ? "PASS" : "FAIL", text === want ? text : `${text} (want ${want})`);
}

async function addressNote() {
  try {
    const text = await noteText("#wb-note-allowed-networks");
    const seen = await clientAddress();
    const want = `The server sees you as ${seen ?? "unknown"}`;
    row("address-note", text === want ? "PASS" : "FAIL", text === want ? text : `${text} (want ${want})`);
  } finally {
    await clickButton("Cancel");
  }
}

// An ordinary save shows its success line and no save warning: the policy reaches no admin.
const checkedSaves = [];
const warnedSaves = [];
const unseenSaves = [];
async function checkNoWarning(step) {
  try {
    await waitFor(`!!document.querySelector(".alert-success.mt-3")`, `${step} success line`);
  } catch {
    unseenSaves.push(step);
    return;
  }
  if (await evalValue(`!!document.querySelector(".wb-save-warning")`)) warnedSaves.push(step);
  checkedSaves.push(step);
}

async function noSaveWarning() {
  const want = "save-controls,edit-policy,swap,block-inheritance,remove,delete-policy";
  if (checkedSaves.join(",") === want && warnedSaves.length === 0) {
    row("no-save-warning", "PASS", `no .wb-save-warning after ${checkedSaves.join(", ")}`);
  } else {
    row("no-save-warning", "FAIL", `checked ${checkedSaves.join(",") || "none"}; warned after ${warnedSaves.join(",") || "none"}; no success line after ${unseenSaves.join(",") || "none"}`);
  }
}

// A phase admin in its own OU links a list that refuses itself: the save stands, with its warning.
async function saveWarning() {
  if (!warnUser || !warnPass || !warnOu || !warnPolicy) throw fail("BROWSER_WARN_USER", "unset");
  await logout();
  await login(warnUser, warnPass);
  await goto("/policies");
  await openEditorOn(warnOu);
  const seen = await clientAddress();
  await fill('input[placeholder="e.g. Front Desk"]', warnPolicy);
  await setRule("allowed-networks", "text", "192.0.2.0/24");
  await clickButton("Save");
  const saved = `Policy ${warnPolicy} set on ${warnOu}`;
  const warned = "allowed-networks: the list that now applies to you does not contain the address " +
    `the server sees you as (${seen ?? "unknown"}). The way back, on the host: lldap policy-unlink ` +
    `--config-file <config> '${warnOu}'`;
  const refused = "The server refused the next request: this session is outside the list now. " +
    "The way back is on the host: lldap policy-unlink, as the warning above names it.";
  const lines = `(() => [...document.querySelectorAll(".alert-success.mt-3, .wb-save-warning")]
    .map((n) => n.textContent.replace(/\\s+/g, " ").trim()))()`;
  const said = `(() => [...document.querySelectorAll("div.alert.alert-warning.mt-3.wb-save-refused")]
    .map((n) => n.textContent.replace(/\\s+/g, " ").trim()))()`;
  try {
    await waitFor(`(${lines}).includes(${JSON.stringify(warned)})`, ".wb-save-warning");
    // The refetch after the save is this session's next request: refused, then said in words.
    await waitFor(`(${said}).length > 0`, ".wb-save-refused");
  } catch {
    // The row below names what was shown.
  }
  const shown = await evalValue(lines);
  const after = await evalValue(said);
  const red = await evalValue(`[...document.querySelectorAll(".alert-danger")].map((n) => n.textContent.trim()).join(" | ")`);
  if (shown.length === 2 && shown[0] === saved && shown[1] === warned &&
    after.length === 1 && after[0] === refused && !red) {
    row("save-warning", "PASS", `${saved} | ${warned} | ${refused}`);
  } else {
    row("save-warning", "FAIL", `${shown.join(" | ") || "nothing"}; refused line: ${after.join(" | ") || "none"}; ` +
      `red: ${red || "none"} (want ${saved} | ${warned}; ${refused}; no red alert)`);
  }
}

async function reloadPage() {
  await send("Page.reload", { ignoreCache: true });
  await waitFor(
    `location.pathname === "/policies" && [...document.querySelectorAll("h5")].some((h) => h.textContent.trim() === "Policies")`,
    "h5 Policies",
  );
  await selectOu(CHILD);
  const detail = await pageValues();
  row("reload-page", "PASS", detail);
}

async function graphqlMatch() {
  await waitPanel();
  const detail = await pageValues();
  await writeFile(`${outDir}/graphql-match.ready`, "ready\n");
  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    try {
      await readFile(`${outDir}/graphql-match.done`);
      row("graphql-match", "PASS", detail);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
  throw fail("graphql-match.done", "the phase did not read effectivePolicyItems");
}

async function editPolicy() {
  await clickButton("Edit");
  await fill('input[placeholder="e.g. Front Desk"]', editedName);
  await fill('input[placeholder="What is this policy for?"]', "desk hours edited");
  await clickButton("Save");
  await waitFor(
    `(() => {
      const card = document.querySelector(".pol-card");
      return !!card && card.textContent.includes(${JSON.stringify(editedName)});
    })()`,
    editedName,
  );
  await checkNoWarning("edit-policy");
  row("edit-policy", "PASS", editedName);
}

async function swapPolicy() {
  await clickButton("New policy");
  await fill('input[placeholder="e.g. Front Desk"]', otherName);
  await setRule("enable-mfa", "select", "off");
  await clickButton("Save");
  await waitFor(
    `document.querySelector(".alert-success")?.textContent.includes(${JSON.stringify(otherName)})`,
    otherName,
  );
  await selectOu(CHILD);
  await clickButton("Swap");
  await clickButton("Use this");
  await waitFor(
    `(() => {
      const card = document.querySelector(".pol-card");
      return !!card && card.textContent.includes(${JSON.stringify(otherName)}) && card.textContent.includes("on this OU");
    })()`,
    otherName,
  );
  await checkNoWarning("swap");
  row("swap", "PASS", otherName);
}

async function blockInheritance() {
  await waitFor(`!!document.querySelector("#wb-block-switch")`, "#wb-block-switch");
  const checked = await evalValue(`document.querySelector("#wb-block-switch").checked`);
  if (!checked) await evalValue(`document.querySelector("#wb-block-switch").click()`);
  await waitFor(`document.querySelector("#wb-block-switch").checked`, "#wb-block-switch");
  await checkNoWarning("block-inheritance");
  row("block-inheritance", "PASS");
}

async function removePolicy() {
  await clickButton("Remove");
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes("Attach a policy") && !b.disabled)`,
    "button Attach a policy",
  );
  await checkNoWarning("remove");
  row("remove", "PASS");
}

async function deletePolicy() {
  await clickButton("Attach a policy");
  await clickButton("Use this");
  await waitFor(
    `(() => {
      const card = document.querySelector(".pol-card");
      return !!card && card.textContent.includes(${JSON.stringify(editedName)});
    })()`,
    editedName,
  );
  await clickButton("Edit");
  await clickButton("Delete this policy everywhere");
  await clickWithin("#deletePolicyModal", "Yes, delete it");
  await waitFor(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.includes("Attach a policy") && !b.disabled)`,
    "button Attach a policy",
  );
  const still = await evalValue(
    `[...document.querySelectorAll(".pol-card")].some((card) => card.textContent.includes(${JSON.stringify(editedName)}))`,
  );
  if (still) throw fail(editedName, "still on the page");
  const deleted = `Policy ${editedName} deleted`;
  await waitFor(
    `[...document.querySelectorAll(".alert-success.mt-3")].some((n) => n.textContent.trim() === ${JSON.stringify(deleted)})`,
    deleted,
  );
  await checkNoWarning("delete-policy");
  row("delete-policy", "PASS", deleted);
}

async function notice() {
  const found = await evalValue(`(() => {
    const versionNode = [...document.querySelectorAll("span")].find((node) =>
      node.textContent.trim().startsWith("KLLDAP version "));
    const version = versionNode
      ? versionNode.textContent.trim().slice("KLLDAP version ".length)
      : "";
    const span = [...document.querySelectorAll("span.small.text-muted")].find((node) =>
      node.textContent.includes("Not enforced yet in "));
    return {
      version,
      text: span ? span.textContent.replace(/\\s+/g, " ").trim() : "",
    };
  })()`);
  const labels = unenforcedKeys
    .map((key) => {
      const item = ITEMS.find((row) => row[0] === key);
      return item ? item[1] : key;
    })
    .join(", ");
  const version = found && found.version;
  const text = (found && found.text) || "";
  const expected =
    unenforcedKeys.length > 0 && version
      ? `Not enforced yet in ${version}: ${labels}. These values are saved and resolve per OU until the enforcement pass.`
      : "";
  if (!text && unenforcedKeys.length === 0) {
    row("notice", "PASS", "the catalog has no unenforced item");
  } else if (expected && text === expected) {
    row("notice", "PASS", text);
  } else {
    row("notice", "FAIL", text || "missing");
  }
}

// Where the server sets enable_mfa, the page says it overrides every OU's enable-mfa.
async function overrideLine() {
  const text = await evalValue(`(() => {
    const span = [...document.querySelectorAll("span.small.text-muted")].find((node) =>
      node.textContent.includes("The server sets enable_mfa"));
    return span ? span.textContent.replace(/\\s+/g, " ").trim() : "";
  })()`);
  const expected = serverWide
    ? `The server sets enable_mfa = ${serverWide} for every user: it overrides the OUs' enable-mfa.`
    : "";
  if (text === expected) {
    row("override-line", "PASS", text || "no server-wide value, no line");
  } else {
    row("override-line", "FAIL", text || "missing");
  }
}

async function emptyName() {
  await clickButton("New policy");
  await clickButton("Save");
  await waitFor(
    `[...document.querySelectorAll("span.text-danger")].some((node) => node.textContent.includes("Policy name must be 1 to 64 characters"))`,
    "Policy name must be 1 to 64 characters",
  );
  await clickButton("Cancel");
  row("empty-name", "PASS", "Policy name must be 1 to 64 characters");
}

async function invalidInt() {
  await clickButton("New policy");
  await fill('input[placeholder="e.g. Front Desk"]', badIntName);
  await setRule("lockout-threshold", "number", "101");
  await clickButton("Save");
  await waitFor(
    `[...document.querySelectorAll("span.text-danger")].some((node) => node.textContent.includes("Failed logins before lockout: must be between 0 and 100"))`,
    "Failed logins before lockout: must be between 0 and 100",
  );
  await clickButton("Cancel");
  row("invalid-int", "PASS", "Failed logins before lockout: must be between 0 and 100");
}

async function invalidString() {
  await clickButton("New policy");
  await fill('input[placeholder="e.g. Front Desk"]', badHoursName);
  await setRule("login-hours", "text", "nope");
  await clickButton("Save");
  await waitFor(
    `document.querySelector(".alert-danger")?.textContent.includes("login-hours entries must be DAY[-DAY] HH:MM-HH:MM")`,
    "login-hours entries must be DAY[-DAY] HH:MM-HH:MM",
  );
  await evalValue(`document.querySelector("#wb-rule-login-hours").click()`);
  await waitFor(`!document.querySelector("#wb-rule-login-hours").checked`, "#wb-rule-login-hours");
  await setRule("allowed-networks", "text", "not-a-cidr");
  await clickButton("Save");
  await waitFor(
    `document.querySelector(".alert-danger")?.textContent.includes("CIDR must include an explicit prefix")`,
    "CIDR must include an explicit prefix",
  );
  const stillEditing = await evalValue(
    `[...document.querySelectorAll("button")].some((b) => b.textContent.trim() === "Save")`,
  );
  if (!stillEditing) throw fail("invalid-string", "the editor closed");
  await clickButton("Cancel");
  row(
    "invalid-string",
    "PASS",
    "login-hours nope refused; allowed-networks not-a-cidr refused",
  );
}

async function refused(name, kind) {
  const link = await evalValue(
    `[...document.querySelectorAll("a")].some((a) => a.textContent.trim() === "Policies")`,
  );
  if (link) throw fail("nav Policies", "the link is present");
  await goto("/policies");
  let text = "";
  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    const now = await evalValue(`(() => {
      const alert = document.querySelector(".alert-danger");
      const workbench = [...document.querySelectorAll("button")].some((b) =>
        b.textContent.includes("New policy"));
      if (workbench) return "WORKBENCH";
      return alert ? alert.textContent.trim() : "";
    })()`);
    if (now === "WORKBENCH") throw fail("button New policy", "the workbench opened");
    if (now && now === text && now.includes("Unauthorized")) {
      row(name, kind, now);
      return;
    }
    text = now;
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw fail(".alert-danger", text || "missing");
}

async function loginPlain() {
  await logout();
  await login(plainUser, plainPass);
  await refused("plain-user", "PASS");
}

async function readOnly() {
  await logout();
  await login(roUser, roPass);
  const link = await evalValue(
    `[...document.querySelectorAll("a")].some((a) => a.textContent.trim() === "Policies")`,
  );
  await goto("/policies");
  let previous = "";
  let shown = "";
  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    const now = await evalValue(`(() => {
      const alert = document.querySelector(".alert-danger");
      const workbench = [...document.querySelectorAll("button")].some((b) =>
        b.textContent.includes("New policy"));
      if (workbench) return "WORKBENCH";
      return alert ? alert.textContent.replace(/\\s+/g, " ").trim() : "";
    })()`);
    if (now && now === previous) {
      shown = now;
      break;
    }
    previous = now || previous;
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  if (!shown) shown = previous;
  const parts = [];
  if (link) parts.push("the Policies link is present");
  if (shown === "WORKBENCH") parts.push("the workbench opened");
  else if (shown) parts.push(shown);
  else parts.push("no alert");
  row("readonly", "NOTE", parts.join("; "));
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

const steps = [
  ["admin-login", adminLogin],
  ["create-ou", createOu],
  ["open-policies", openPolicies],
  ["zone-note", zoneNote],
  ["address-note", addressNote],
  ["save-controls", saveControls],
  ["reload-page", reloadPage],
  ["graphql-match", graphqlMatch],
  ["edit-policy", editPolicy],
  ["swap", swapPolicy],
  ["block-inheritance", blockInheritance],
  ["remove", removePolicy],
  ["delete-policy", deletePolicy],
  ["no-save-warning", noSaveWarning],
  ["notice", notice],
  ["override-line", overrideLine],
  ["empty-name", emptyName],
  ["invalid-int", invalidInt],
  ["invalid-string", invalidString],
  ["plain-user", loginPlain],
  ["readonly", readOnly],
  ["save-warning", saveWarning],
];

let failed = false;
try {
  if (!primary || !CHILD || !frontName || !editedName || !otherName || !badIntName || !badHoursName) {
    throw fail("BROWSER_PRIMARY", "unset");
  }
  await connect();
  for (const [name, fn] of steps) {
    currentStep = name;
    if (pagePanicked && !said.has(name)) {
      row(name, "NOTE", "not reached: policies page panicked");
      continue;
    }
    try {
      await fn();
    } catch (err) {
      failed = true;
      if (!said.has(name)) {
        const alert = err.alert ? ` ${err.alert}` : "";
        row(name, "FAIL", `${err.selector || "unknown"}${alert} ${err.message || ""}`);
      }
      await screenshot(name);
      await writeConsole(name);
    }
  }
} catch (err) {
  failed = true;
  if (!said.has(currentStep)) {
    row(currentStep, "FAIL", `${err.selector || "unknown"} ${err.message || ""}`);
  }
  await screenshot(currentStep);
  await writeConsole(currentStep);
} finally {
  if (chrome && !chrome.killed) chrome.kill("SIGTERM");
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
}
process.exit(failed ? 1 : 0);
