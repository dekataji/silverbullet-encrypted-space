// encrypted-space.plug.js — "Encrypted Space" for SilverBullet v2.
// E2E: AES-256-GCM + PBKDF2-SHA256 (600k iterations). Files `*.enc.md` hold ciphertext.
// Unlock once -> all notes decrypted into session memory + the browser index
// (native queries work). Server/repo: ciphertext only, forever.
// NEVER store the password on disk. Lock: wipe memory + clearFileIndex.

// ================= worker bootstrap (plug protocol) =================
let __seq = 0;
const __pending = new Map();
function __post(m) { self.postMessage(m); }
globalThis.syscall = (name, ...args) => new Promise((resolve, reject) => {
  const id = ++__seq;
  __pending.set(id, { resolve, reject });
  __post({ type: "sys", id, name, args });
});
self.addEventListener("message", (ev) => {
  (async () => {
    const m = ev.data;
    if (!m || typeof m !== "object") return;
    if (m.type === "inv") {
      const fn = FUNCTIONS[m.name];
      if (!fn) { __post({ type: "invr", id: m.id, error: "Function not loaded: " + m.name }); return; }
      try {
        __post({ type: "invr", id: m.id, result: await fn(...(m.args || [])) });
      } catch (e) {
        __post({ type: "invr", id: m.id, error: String((e && e.message) || e) });
      }
    } else if (m.type === "sysr") {
      const p = __pending.get(m.id);
      if (!p) return;
      __pending.delete(m.id);
      if (m.error) p.reject(new Error(m.error)); else p.resolve(m.result);
    }
  })().catch((e) => console.error("[encspace]", e));
});

// ================= syscalls =================
const syscall = (name, ...args) => globalThis.syscall(name, ...args);
const editor = {
  prompt: (msg, def = "") => syscall("editor.prompt", msg, def),
  filterBox: (label, options, help = "", ph = "") => syscall("editor.filterBox", label, options, help, ph),
  flashNotification: (msg, type = "info") => syscall("editor.flashNotification", msg, type),
  confirm: (msg) => syscall("editor.confirm", msg),
  showPanel: (id, mode, html, script = "") => syscall("editor.showPanel", id, mode, html, script),
  hidePanel: (id) => syscall("editor.hidePanel", id),
};
const space = {
  listFiles: () => syscall("space.listFiles"),
  readFile: (name) => syscall("space.readFile", name),
  writeFile: (name, data) => syscall("space.writeFile", name, data),
  getCurrentPage: () => syscall("editor.getCurrentPage"),
};
async function readPageText(page) {
  try {
    const t = await syscall("space.readPage", page);
    if (typeof t === "string") return t;
  } catch (e) { /* fallback */ }
  return readText(page + ".md");
}
async function deletePageFile(page) {
  try { await syscall("space.deletePage", page); return; }
  catch (e) { /* fallback */ }
  await syscall("space.deleteFile", page + ".md");
}
const index = {
  indexObjects: (page, objects) => syscall("index.indexObjects", page, objects),
  clearFileIndex: (path) => syscall("index.clearFileIndex", path),
};

// ================= crypto (pure) =================
const te = new TextEncoder();
const td = new TextDecoder();
function b64e(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}
function b64d(s) {
  const bin = atob(s);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}
function randBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
}
async function encEncrypt(password, title, body) {
  const salt = randBytes(16), iv = randBytes(12);
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(JSON.stringify({ title, body })));
  return JSON.stringify({ v: 1, salt: b64e(salt), iv: b64e(iv), ct: b64e(ct) });
}
async function encDecrypt(password, envelopeJson) {
  const env = JSON.parse(envelopeJson);
  if (!env || env.v !== 1 || !env.salt || !env.iv || !env.ct) throw new Error("envelope rusak");
  const key = await deriveKey(password, b64d(env.salt));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(env.iv) }, key, b64d(env.ct));
  const obj = JSON.parse(td.decode(pt));
  if (typeof obj.title !== "string" || typeof obj.body !== "string") throw new Error("payload rusak");
  return obj;
}
function randomEncName() {
  return [...randBytes(6)].map((b) => b.toString(16).padStart(2, "0")).join("") + ".enc.md";
}

// ================= session state (memory only) =================
let _password = null;          // master password, never persisted
let _vault = new Map();        // filename -> {title, body}
let _unlocked = false;
let _reindexTimer = null;
const VERIFIER = "Library/EncryptedSpace/verifier.json";
const ENC_SUFFIX = ".enc.md";

async function readText(name) {
  const b = await space.readFile(name);
  return td.decode(b instanceof Uint8Array ? b : new Uint8Array(b));
}
async function writeText(name, text) {
  return space.writeFile(name, te.encode(text));
}
async function listEncFiles() {
  const files = await space.listFiles();
  return files.map((f) => f.name).filter((n) => typeof n === "string" && n.endsWith(ENC_SUFFIX));
}
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
async function requireUnlock() {
  if (_unlocked) return true;
  await editor.flashNotification("Encrypted Space is locked — run 'Encrypted Space: Unlock' first", "error");
  return false;
}

// ================= index =================
function parseTasks(body) {
  const tasks = [];
  const lines = body.split("\n");
  const re = /^(\s*)([-*]|\d+[.)])\s+\[([ xX])\]\s+(.*)$/;
  let offset = 0;
  lines.forEach((line) => {
    const m = re.exec(line);
    if (m) tasks.push({ offset, text: m[4], done: m[3].toLowerCase() === "x" });
    offset += line.length + 1;
  });
  return tasks;
}
async function indexNote(file, title, body) {
  const objects = [];
  for (const t of parseTasks(body)) {
    objects.push({ ref: `${file}@${t.offset}`, tag: "task", name: t.text, done: t.done, page: file });
  }
  if (!objects.length) return;
  try {
    await index.indexObjects(file, objects);
  } catch (e) {
    console.error("[encspace] index gagal:", file, e);
  }
}
async function clearNoteIndex(file) {
  try { await index.clearFileIndex(file); } catch (e) { /* abaikan */ }
}

// ================= commands =================
async function unlock() {
  if (_unlocked) { await editor.flashNotification("Encrypted Space is already unlocked"); return; }
  const pw = await editor.prompt("Encrypted Space — master password:");
  if (!pw) return;
  const files = await listEncFiles();
  let ok = false;
  if (files.length) {
    for (const f of files.slice(0, 3)) {
      try { await encDecrypt(pw, await readText(f)); ok = true; break; }
      catch (e) { /* coba file liya */ }
    }
  } else {
    try {
      await encDecrypt(pw, await readText(VERIFIER));
      ok = true;
    } catch (e) {
      try { await writeText(VERIFIER, await encEncrypt(pw, "__verifier__", "ok")); } catch (e2) { /* best effort */ }
      ok = true;
    }
  }
  if (!ok) { await editor.flashNotification("Wrong password", "error"); return; }
  _password = pw;
  _vault = new Map();
  let gagal = 0;
  for (const f of files) {
    try {
      const { title, body } = await encDecrypt(pw, await readText(f));
      _vault.set(f, { title, body });
      await clearNoteIndex(f);
      await indexNote(f, title, body);
    } catch (e) { gagal++; console.error("[encspace] gagal dekripsi:", f, e); }
  }
  _unlocked = true;
  await editor.flashNotification(
    `Encrypted Space unlocked: ${_vault.size} note(s)${gagal ? ` (${gagal} failed)` : ""}`
  );
}

async function lock() {
  if (!_unlocked) { await editor.flashNotification("Encrypted Space is already locked"); return; }
  for (const f of _vault.keys()) await clearNoteIndex(f);
  _vault = new Map();
  _password = null;
  _unlocked = false;
  await editor.flashNotification("Encrypted Space locked — memory wiped");
}

async function pickNote() {
  const entries = [..._vault.entries()];
  if (!entries.length) { await editor.flashNotification("No encrypted notes", "error"); return null; }
  const labels = entries.map(([f, v]) => `${v.title}  (${f})`);
  const pick = await editor.filterBox("Encrypted Space — pick a note:", labels, "", "type to search...");
  if (!pick) return null;
  const idx = labels.indexOf(pick);
  if (idx < 0) return null;
  return entries[idx][0];
}

function mdPreview(title, body) {
  // Minimal render: escape + headers/bold/tasks
  let h = esc(body)
    .replace(/^###### (.*)$/gm, "<h6>$1</h6>").replace(/^##### (.*)$/gm, "<h5>$1</h5>")
    .replace(/^#### (.*)$/gm, "<h4>$1</h4>").replace(/^### (.*)$/gm, "<h3>$1</h3>")
    .replace(/^## (.*)$/gm, "<h2>$1</h2>").replace(/^# (.*)$/gm, "<h1>$1</h1>")
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`(.+?)`/g, "<code>$1</code>")
    .replace(/^- \[x\] (.*)$/gim, "<div>☑ $1</div>").replace(/^- \[ \] (.*)$/gim, "<div>☐ $1</div>");
  return `<div style="font-family:sans-serif;max-width:640px;margin:0 auto;padding:20px">`
    + `<h2 style="margin-top:0">${esc(title)} <span style="font-size:12px;color:#888">🔒</span></h2>`
    + `<div style="white-space:pre-wrap;line-height:1.6">${h}</div>`
    + `<p style="color:#888;font-size:12px">Close this panel when done (click outside / Esc).</p></div>`;
}

async function openNote() {
  if (!await requireUnlock()) return;
  const f = await pickNote();
  if (!f) return;
  const { title, body } = _vault.get(f);
  await editor.showPanel("modal", "0 0 640px", mdPreview(title, body), "");
}

async function newNote() {
  if (!await requireUnlock()) return;
  const title = await editor.prompt("Secret note title:");
  if (!title) return;
  const existing = new Set(await listEncFiles());
  let name;
  do { name = randomEncName(); } while (existing.has(name));
  const body = "# " + title + "\n";
  await writeText(name, await encEncrypt(_password, title, body));
  _vault.set(name, { title, body });
  await clearNoteIndex(name);
  await indexNote(name, title, body);
  await editor.flashNotification("Encrypted note created: " + title);
  await openEditorModal(name);
}

async function openEditorModal(file) {
  const entry = _vault.get(file);
  if (!entry) return;
  // Per-file key for the panel script (no plaintext in the script)
  const env = JSON.parse(await readText(file));
  const key = await deriveKey(_password, b64d(env.salt));
  const keyB64 = b64e(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
  const fsPath = file.split("/").map(encodeURIComponent).join("/");
  const html =
    `<div style="font-family:sans-serif;max-width:640px;margin:0 auto;padding:20px">`
    + `<h3 style="margin-top:0">✏️ ${esc(entry.title)} <span style="font-size:12px;color:#888">🔒</span></h3>`
    + `<input id="es-title" value="${esc(entry.title)}" style="width:100%;padding:8px;margin-bottom:8px;font-size:15px"/>`
    + `<textarea id="es-body" style="width:100%;height:50vh;padding:8px;font-family:monospace;font-size:14px">${esc(entry.body)}</textarea>`
    + `<div style="margin-top:10px;display:flex;gap:8px;align-items:center">`
    + `<button id="es-save" style="padding:8px 16px">Save (encrypt)</button>`
    + `<span id="es-msg" style="font-size:13px;color:#555"></span></div>`
    + `<p style="color:#888;font-size:12px">Saved directly encrypted (AES-256-GCM). No plaintext ever touches the server.</p></div>`;
  const script = `(async()=>{`
    + `const KEY=${JSON.stringify(keyB64)},SALT=${JSON.stringify(env.salt)},FNAME=${JSON.stringify(fsPath)};`
    + `const te=new TextEncoder();`
    + `const b64d=s=>{const b=atob(s),o=new Uint8Array(b.length);for(let i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;};`
    + `const b64e=b=>{let s="";const o=new Uint8Array(b);for(let i=0;i<o.length;i++)s+=String.fromCharCode(o[i]);return btoa(s);};`
    + `document.getElementById("es-save").addEventListener("click",async()=>{`
    + `const btn=document.getElementById("es-save"),msg=document.getElementById("es-msg");`
    + `btn.disabled=true;btn.textContent="Saving...";msg.textContent="";`
    + `try{`
    + `const title=document.getElementById("es-title").value,body=document.getElementById("es-body").value;`
    + `const key=await crypto.subtle.importKey("raw",b64d(KEY),"AES-GCM",false,["encrypt"]);`
    + `const iv=crypto.getRandomValues(new Uint8Array(12));`
    + `const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,te.encode(JSON.stringify({title,body})));`
    + `const env=JSON.stringify({v:1,salt:SALT,iv:b64e(iv),ct:b64e(ct)});`
    + `const r=await fetch("/.fs/"+FNAME,{method:"PUT",body:env,headers:{"Content-Type":"application/json"}});`
    + `if(!r.ok)throw new Error("HTTP "+r.status);`
    + `msg.textContent="✓ Saved encrypted. You can close this panel.";`
    + `}catch(e){msg.textContent="Save failed: "+(e.message||e);btn.disabled=false;btn.textContent="Save (encrypt)";}`
    + `});})();`;
  await editor.showPanel("modal", "0 0 640px", html, script);
}

async function editNote() {
  if (!await requireUnlock()) return;
  const f = await pickNote();
  if (!f) return;
  await openEditorModal(f);
}

// Convert a regular note (current page) to encrypted
async function convertNote() {
  if (!await requireUnlock()) return;
  const page = await space.getCurrentPage();
  if (!page) { await editor.flashNotification("No page is open", "error"); return; }
  if (page.endsWith(".enc")) { await editor.flashNotification("This note is already encrypted", "error"); return; }
  let body;
  try { body = await readPageText(page); }
  catch (e) { await editor.flashNotification("Could not read page: " + page, "error"); return; }
  const base = page.includes("/") ? page.split("/").pop() : page;
  const dir = page.includes("/") ? page.split("/").slice(0, -1).join("/") + "/" : "";
  const existing = new Set(await listEncFiles());
  let name;
  do { name = dir + randomEncName(); } while (existing.has(name));
  await writeText(name, await encEncrypt(_password, base, body));
  _vault.set(name, { title: base, body });
  await clearNoteIndex(name);
  await indexNote(name, base, body);
  const del = await editor.confirm(
    `Encrypted copy created. Delete the original plaintext note "${page}"?\n(Git history keeps old plaintext versions regardless.)`
  );
  if (del) {
    try { await deletePageFile(page); }
    catch (e) { await editor.flashNotification("Encrypted copy saved, but original could not be deleted", "error"); return; }
  }
  await editor.flashNotification(del ? "Note converted to encrypted" : "Encrypted copy created (original kept)");
}

// Auto re-index when an .enc.md file changes (e.g. saved from the modal)
async function onPageIndex(ev) {
  try {
    if (!_unlocked || !_password) return;
    const name = ev && (ev.name || ev.page || (ev.path || ""));
    if (typeof name !== "string" || !name.endsWith(ENC_SUFFIX)) return;
    if (_reindexTimer) clearTimeout(_reindexTimer);
    _reindexTimer = setTimeout(async () => {
      try {
        const { title, body } = await encDecrypt(_password, await readText(name));
        _vault.set(name, { title, body });
        await clearNoteIndex(name);
        await indexNote(name, title, body);
      } catch (e) { /* abaikan */ }
    }, 1200);
  } catch (e) { /* abaikan */ }
}

// ================= manifest & registration =================
const MANIFEST = {
  name: "encrypted-space",
  functions: {
    unlock: { path: "encrypted-space.ts:unlock", command: { name: "Encrypted Space: Unlock" } },
    lock: { path: "encrypted-space.ts:lock", command: { name: "Encrypted Space: Lock" } },
    newNote: { path: "encrypted-space.ts:newNote", command: { name: "Encrypted Space: New note" } },
    openNote: { path: "encrypted-space.ts:openNote", command: { name: "Encrypted Space: Open note" } },
    editNote: { path: "encrypted-space.ts:editNote", command: { name: "Encrypted Space: Edit note" } },
    convertNote: { path: "encrypted-space.ts:convertNote", command: { name: "Encrypted Space: Convert current note to encrypted" } },
    onPageIndex: { path: "encrypted-space.ts:onPageIndex", events: ["page:index"] },
  },
  assets: {},
};
const FUNCTIONS = { unlock, lock, newNote, openNote, editNote, convertNote, onPageIndex };
__post({ type: "manifest", manifest: MANIFEST });
export const plug = { manifest: MANIFEST, functionMapping: FUNCTIONS };
