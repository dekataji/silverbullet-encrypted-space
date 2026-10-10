// Inti kripto "encrypted space" — murni, tanpa dependensi SilverBullet.
// Envelope: {"v":1,"salt":b64,"iv":b64,"ct":b64} ; ct = AES-GCM(JSON{title,body})
// Kunci: PBKDF2-SHA256 600k iterasi -> AES-256-GCM.

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
function rand(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 600000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

/** @returns {string} envelope JSON */
export async function encEncrypt(password, title, body) {
  const salt = rand(16), iv = rand(12);
  const key = await deriveKey(password, salt);
  const pt = te.encode(JSON.stringify({ title, body }));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
  return JSON.stringify({ v: 1, salt: b64e(salt), iv: b64e(iv), ct: b64e(ct) });
}

/** @returns {{title:string, body:string}} ; throws yen password salah / rusak */
export async function encDecrypt(password, envelopeJson) {
  const env = JSON.parse(envelopeJson);
  if (!env || env.v !== 1 || !env.salt || !env.iv || !env.ct) throw new Error("envelope rusak");
  const key = await deriveKey(password, b64d(env.salt));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(env.iv) }, key, b64d(env.ct));
  const obj = JSON.parse(td.decode(pt));
  if (typeof obj.title !== "string" || typeof obj.body !== "string") throw new Error("payload rusak");
  return obj;
}

/** basename acak kanggo panyamaran: 12 hex char + .enc.md */
export function randomEncName() {
  return [...rand(6)].map(b => b.toString(16).padStart(2, "0")).join("") + ".enc.md";
}
