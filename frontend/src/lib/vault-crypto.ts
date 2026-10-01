/** The vault's cryptography, all of it, in the browser.
 *
 *  The server stores what leaves this file and can do nothing else with it.
 *  That is the whole design, so the parts worth being strict about are here:
 *
 *  - The passphrase is stretched with Argon2id, not a hash iteration count.
 *    The sealed private key is the one thing an attacker with the database
 *    can grind offline, and memory-hardness is what makes that expensive on
 *    the hardware they would actually use.
 *  - Nothing derived is ever written to storage. The unwrapped key lives in a
 *    module variable, which dies with the tab.
 *  - Every sealed blob is bound to where it belongs, so a ciphertext lifted
 *    from another item or another vault fails to open rather than decrypting
 *    into the wrong row.
 */

import { argon2id } from "hash-wasm";

/** The floor the backend also enforces. Stored next to the blob so it can be
 *  raised later without stranding everything sealed under the old numbers. */
export const KDF_PARAMS = { alg: "argon2id", m: 65536, t: 3, p: 1 } as const;

const WRAP_INFO = "kubecommit-vault-key-wrap-v1";
const EPH_KEY_BYTES = 65; // uncompressed P-256 point
const NONCE_BYTES = 12;

const enc = new TextEncoder();
const dec = new TextDecoder();

/** TypeScript 5.7 made Uint8Array generic over its backing buffer, and the
 *  WebCrypto signatures accept only the plain-ArrayBuffer flavour. Views that
 *  come back from slice(), or out of a wasm module, are typed loosely; they
 *  are narrowed here rather than at twenty call sites. */
type Bytes = Uint8Array<ArrayBuffer>;
const bytes = (b: Uint8Array): Bytes => b as Bytes;

// ---- encoding ------------------------------------------------------------

export function toB64(input: ArrayBuffer | Uint8Array): string {
  const view = input instanceof Uint8Array ? input : new Uint8Array(input);
  let s = "";
  for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
  return btoa(s);
}

export function fromB64(b64: string): Bytes {
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function toHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export function randomBytes(n: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---- passphrase ----------------------------------------------------------

/** Argon2id over the passphrase, into an AES-GCM key that cannot be exported.
 *  Non-extractable matters less than it looks -- the whole tab is trusted --
 *  but it means a stray console.log cannot print the key. */
export async function deriveWrappingKey(
  passphrase: string,
  salt: Uint8Array,
  params: { m: number; t: number; p: number } = KDF_PARAMS
): Promise<CryptoKey> {
  const raw = await argon2id({
    password: passphrase,
    salt,
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m, // KiB
    hashLength: 32,
    outputType: "binary",
  });
  return crypto.subtle.importKey("raw", bytes(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

// ---- AES-GCM -------------------------------------------------------------

/** nonce || ciphertext, base64. The nonce is random per seal and never
 *  reused, which is the one thing GCM cannot survive. */
async function seal(key: CryptoKey, plaintext: Bytes, aad: string): Promise<string> {
  const nonce = randomBytes(NONCE_BYTES);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: enc.encode(aad) },
    key,
    plaintext
  );
  const out = new Uint8Array(NONCE_BYTES + ct.byteLength);
  out.set(nonce, 0);
  out.set(new Uint8Array(ct), NONCE_BYTES);
  return toB64(out);
}

async function open(key: CryptoKey, blob: string, aad: string): Promise<Bytes> {
  const raw = fromB64(blob);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bytes(raw.slice(0, NONCE_BYTES)), additionalData: enc.encode(aad) },
    key,
    bytes(raw.slice(NONCE_BYTES))
  );
  return new Uint8Array(plain);
}

// ---- identity ------------------------------------------------------------

export interface Enrolment {
  publicKey: string;
  fingerprint: string;
  privateKeyEnc: string;
  kdfSalt: string;
  kdfParams: string;
  recoveryKeyEnc: string;
  recoverySalt: string;
  recoveryCode: string;
  privateKey: CryptoKey;
}

/** SHA-256 over the public key. The server is what hands public keys out,
 *  which makes it the one party able to substitute one; a fingerprint two
 *  people compare out of band is the only thing that catches that, so it is
 *  computed here rather than trusted from the response. */
export async function fingerprintOf(publicKeySpki: Bytes): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", publicKeySpki));
}

/** Seals one freshly generated private key twice: once under the passphrase,
 *  once under a recovery code. Two independent ways into the same identity,
 *  so forgetting one costs a piece of paper instead of everything. */
export async function enrol(passphrase: string): Promise<Enrolment> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));

  const kdfSalt = randomBytes(16);
  const recoverySalt = randomBytes(16);
  const recoveryCode = generateRecoveryCode();

  const passKey = await deriveWrappingKey(passphrase, kdfSalt);
  const recKey = await deriveWrappingKey(recoveryCode, recoverySalt);
  const fingerprint = await fingerprintOf(spki);

  // The identity is bound into its own wrapping, so a private key cannot be
  // swapped for another person's without the unwrap failing outright.
  const aad = `identity:${fingerprint}`;

  return {
    publicKey: toB64(spki),
    fingerprint,
    privateKeyEnc: await seal(passKey, pkcs8, aad),
    kdfSalt: toB64(kdfSalt),
    kdfParams: JSON.stringify(KDF_PARAMS),
    recoveryKeyEnc: await seal(recKey, pkcs8, aad),
    recoverySalt: toB64(recoverySalt),
    recoveryCode,
    privateKey: await importPrivate(pkcs8),
  };
}

async function importPrivate(pkcs8: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
}

/** Unseals the identity. A wrong passphrase surfaces as a failed GCM tag,
 *  which is the only check there is -- deliberately, because a verifier
 *  stored alongside would be one more thing to grind offline. */
export async function unsealIdentity(
  secret: string,
  blobEnc: string,
  salt: string,
  fingerprint: string,
  params: { m: number; t: number; p: number } = KDF_PARAMS
): Promise<Bytes> {
  const key = await deriveWrappingKey(secret, fromB64(salt), params);
  return open(key, blobEnc, `identity:${fingerprint}`);
}

export async function unlockIdentity(
  secret: string,
  blobEnc: string,
  salt: string,
  fingerprint: string,
  params: { m: number; t: number; p: number } = KDF_PARAMS
): Promise<CryptoKey> {
  return importPrivate(await unsealIdentity(secret, blobEnc, salt, fingerprint, params));
}

/** Reseals the same identity under a new passphrase. The keypair is kept, so
 *  every vault key stays sealed to the same public key and changing a
 *  passphrase never means re-sharing anything. */
export async function reseal(privateKeyPkcs8: Bytes, fingerprint: string, secret: string) {
  const salt = randomBytes(16);
  const key = await deriveWrappingKey(secret, salt);
  return {
    blob: await seal(key, privateKeyPkcs8, `identity:${fingerprint}`),
    salt: toB64(salt),
  };
}

// ---- vault keys ----------------------------------------------------------

/** Seals a vault key to somebody's public key, with nobody else present: an
 *  ephemeral keypair, one ECDH, and HKDF to a key used once. The ephemeral
 *  public key rides along in front of the box, which is what lets the
 *  recipient redo the exchange alone. */
export async function wrapVaultKey(
  recipientSpki: Bytes,
  vaultKeyRaw: Bytes,
  vaultUUID: string,
  recipientFingerprint: string
): Promise<string> {
  const recipient = await crypto.subtle.importKey(
    "spki",
    recipientSpki,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: recipient },
    eph.privateKey,
    256
  );
  const kek = await hkdfKey(shared);
  const ephRaw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));

  // Bound to both the vault and the recipient, so a wrapped key cannot be
  // moved to another vault or replayed at a different person by the server.
  const aad = `wrap:${vaultUUID}:${recipientFingerprint}`;
  const boxed = fromB64(await seal(kek, vaultKeyRaw, aad));

  const out = new Uint8Array(EPH_KEY_BYTES + boxed.length);
  out.set(ephRaw, 0);
  out.set(boxed, EPH_KEY_BYTES);
  return toB64(out);
}

/** The raw vault key. Sharing needs the bytes themselves -- they have to be
 *  resealed to somebody else's public key -- which the CryptoKey below
 *  deliberately cannot give back. Callers that only encrypt items should use
 *  unwrapVaultKey and let the key stay non-extractable. */
export async function unwrapVaultKeyRaw(
  privateKey: CryptoKey,
  wrapped: string,
  vaultUUID: string,
  myFingerprint: string
): Promise<Bytes> {
  const raw = fromB64(wrapped);
  const eph = await crypto.subtle.importKey(
    "raw",
    bytes(raw.slice(0, EPH_KEY_BYTES)),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: eph }, privateKey, 256);
  const kek = await hkdfKey(shared);
  return open(kek, toB64(raw.slice(EPH_KEY_BYTES)), `wrap:${vaultUUID}:${myFingerprint}`);
}

export async function unwrapVaultKey(
  privateKey: CryptoKey,
  wrapped: string,
  vaultUUID: string,
  myFingerprint: string
): Promise<CryptoKey> {
  const keyRaw = await unwrapVaultKeyRaw(privateKey, wrapped, vaultUUID, myFingerprint);
  return crypto.subtle.importKey("raw", keyRaw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function hkdfKey(shared: ArrayBuffer): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(WRAP_INFO) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export function newVaultKeyRaw(): Bytes {
  return randomBytes(32);
}

// ---- items ---------------------------------------------------------------

export interface ItemOverview {
  name: string;
  username?: string;
  url?: string;
  tags?: string[];
}

export interface ItemSecret {
  password?: string;
  notes?: string;
  fields?: { label: string; value: string }[];
}

/** Padded to a multiple of 256 bytes before sealing. GCM does not hide length,
 *  and an unpadded blob leaks roughly how long a password is to anyone reading
 *  the database -- which is a real hint when the answer is "12 characters". */
function pad(plain: Bytes): Bytes {
  const block = 256;
  const total = (Math.floor(plain.length / block) + 1) * block;
  const out = new Uint8Array(total);
  out.set(plain, 0);
  // Length-prefixed rather than delimiter-padded: JSON can contain anything.
  new DataView(out.buffer).setUint32(total - 4, plain.length);
  return out;
}

function unpad(padded: Bytes): Bytes {
  const len = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(
    padded.length - 4
  );
  return bytes(padded.slice(0, len));
}

/** The two halves are sealed separately and bound to different labels, so the
 *  server cannot hand back the overview when the secret was asked for -- which
 *  is what would quietly turn the audited read into an unaudited one. */
const aadFor = (vaultUUID: string, itemUUID: string, part: "overview" | "secret") =>
  `item:${vaultUUID}:${itemUUID}:${part}`;

export async function sealOverview(key: CryptoKey, v: string, i: string, o: ItemOverview) {
  return seal(key, pad(bytes(enc.encode(JSON.stringify(o)))), aadFor(v, i, "overview"));
}
export async function openOverview(key: CryptoKey, v: string, i: string, blob: string) {
  return JSON.parse(dec.decode(unpad(await open(key, blob, aadFor(v, i, "overview"))))) as ItemOverview;
}
export async function sealSecret(key: CryptoKey, v: string, i: string, s: ItemSecret) {
  return seal(key, pad(bytes(enc.encode(JSON.stringify(s)))), aadFor(v, i, "secret"));
}
export async function openSecret(key: CryptoKey, v: string, i: string, blob: string) {
  return JSON.parse(dec.decode(unpad(await open(key, blob, aadFor(v, i, "secret"))))) as ItemSecret;
}

// ---- recovery code -------------------------------------------------------

/** Crockford base32: no I, L, O or U, so it survives being read aloud and
 *  written down. 160 bits, which is well past anything worth grinding. */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function generateRecoveryCode(): string {
  const bytes = randomBytes(20);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += ALPHABET[bytes[i] & 31];
    out += ALPHABET[(bytes[i] >> 3) & 31];
  }
  return (out.match(/.{1,5}/g) ?? []).join("-");
}

/** Accepts what somebody actually types: any spacing, any case, and the
 *  substitutions a person makes reading a code off paper. */
export function normaliseRecoveryCode(input: string): string {
  return (
    input
      .toUpperCase()
      .replace(/[^0-9A-Z]/g, "")
      // The substitutions Crockford defines, so a code read off paper still
      // works when somebody types the letter they saw rather than the digit.
      .replace(/O/g, "0")
      .replace(/[IL]/g, "1")
      .replace(/U/g, "V")
      .match(/.{1,5}/g)
      ?.join("-") ?? ""
  );
}

// ---- password generator --------------------------------------------------

/** Rejection sampling, not modulo. Modulo over a 62-character alphabet makes
 *  the first few characters measurably likelier, which is a needless bias in
 *  the one place the product is supposed to be careful. */
export function generatePassword(length = 24, symbols = true): string {
  const alphabet =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
    (symbols ? "!@#$%^&*()-_=+[]{}<>?" : "");
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < length) {
    for (const b of randomBytes(length)) {
      if (b >= limit) continue;
      out += alphabet[b % alphabet.length];
      if (out.length === length) break;
    }
  }
  return out;
}
