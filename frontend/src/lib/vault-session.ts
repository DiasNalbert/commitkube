/** What is unlocked, and for how long.
 *
 *  The unwrapped identity lives in a module variable and nowhere else. Not
 *  localStorage, not sessionStorage, not a cookie: anything written down can
 *  be read back by script that should not be running, and the one guarantee
 *  this feature makes is that the plaintext exists only while somebody is
 *  looking at it. Closing the tab is a complete logout.
 */

import { apiFetch } from "./api";
import {
  enrol,
  fingerprintOf,
  fromB64,
  KDF_PARAMS,
  newVaultKeyRaw,
  reseal,
  unlockIdentity,
  unsealIdentity,
  unwrapVaultKey,
  unwrapVaultKeyRaw,
  wrapVaultKey,
} from "./vault-crypto";

export interface Keyring {
  user_id: number;
  public_key: string;
  fingerprint: string;
  private_key_enc: string;
  kdf_salt: string;
  kdf_params: string;
  recovery_used: boolean;
}

export interface VaultSummary {
  uuid: string;
  name: string;
  description: string;
  kind: "personal" | "group";
  group_id: number | null;
  role: "owner" | "writer" | "reader";
  wrapped_key: string;
  item_count: number;
  member_count: number;
}

/** Ten minutes. Long enough to copy a password and go back for a second one,
 *  short enough that a walked-away-from laptop is not an open vault. */
const LOCK_AFTER_MS = 10 * 60 * 1000;

let identity: CryptoKey | null = null;
let fingerprint = "";
let vaultKeys = new Map<string, CryptoKey>();
let lockTimer: ReturnType<typeof setTimeout> | null = null;
const listeners = new Set<(unlocked: boolean) => void>();

function announce() {
  for (const fn of listeners) fn(identity !== null);
}

export function onLockChange(fn: (unlocked: boolean) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function isUnlocked(): boolean {
  return identity !== null;
}

export function myFingerprint(): string {
  return fingerprint;
}

export function lock() {
  identity = null;
  fingerprint = "";
  vaultKeys = new Map();
  if (lockTimer) clearTimeout(lockTimer);
  lockTimer = null;
  announce();
}

/** Called on every vault interaction. The countdown is to the last time the
 *  person did something here, not to the unlock -- otherwise the vault locks
 *  in the middle of the work it was unlocked for. */
export function touch() {
  if (!identity) return;
  if (lockTimer) clearTimeout(lockTimer);
  lockTimer = setTimeout(lock, LOCK_AFTER_MS);
}

export async function fetchKeyring(): Promise<Keyring | null> {
  const res = await apiFetch("/vault/keyring");
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("could not load your vault keys");
  return res.json();
}

function kdfOf(keyring: Keyring) {
  try {
    const p = JSON.parse(keyring.kdf_params);
    return { m: p.m ?? KDF_PARAMS.m, t: p.t ?? KDF_PARAMS.t, p: p.p ?? KDF_PARAMS.p };
  } catch {
    return { ...KDF_PARAMS };
  }
}

/** Unlocks with the passphrase. A wrong one fails as a GCM tag mismatch,
 *  which is indistinguishable from any other failure to open -- there is no
 *  oracle here to tell an attacker they are getting warmer. */
export async function unlock(keyring: Keyring, passphrase: string): Promise<void> {
  identity = await unlockIdentity(
    passphrase,
    keyring.private_key_enc,
    keyring.kdf_salt,
    keyring.fingerprint,
    kdfOf(keyring)
  );
  fingerprint = keyring.fingerprint;
  touch();
  announce();
}

/** First-time setup. The recovery code is returned once, to be shown once:
 *  it is never sent to the server in any form it could be read from. */
export async function setUpVault(passphrase: string): Promise<string> {
  const e = await enrol(passphrase);
  const res = await apiFetch("/vault/keyring", {
    method: "POST",
    body: JSON.stringify({
      public_key: e.publicKey,
      fingerprint: e.fingerprint,
      private_key_enc: e.privateKeyEnc,
      kdf_salt: e.kdfSalt,
      kdf_params: e.kdfParams,
      recovery_key_enc: e.recoveryKeyEnc,
      recovery_salt: e.recoverySalt,
    }),
  });
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    throw new Error(j.error || "could not set up the vault");
  }
  identity = e.privateKey;
  fingerprint = e.fingerprint;
  touch();
  announce();
  return e.recoveryCode;
}

/** Changing a passphrase reseals the same identity, so every vault key stays
 *  sealed to the same public key and nothing has to be re-shared. The old
 *  passphrase is required rather than the session being trusted: the point of
 *  the prompt is to prove it is still the same person at the keyboard. */
export async function changePassphrase(
  keyring: Keyring,
  oldPassphrase: string,
  newPassphrase: string
): Promise<void> {
  const pkcs8 = await unsealIdentity(
    oldPassphrase,
    keyring.private_key_enc,
    keyring.kdf_salt,
    keyring.fingerprint,
    kdfOf(keyring)
  );
  const sealed = await reseal(pkcs8, keyring.fingerprint, newPassphrase);
  const res = await apiFetch("/vault/keyring", {
    method: "PUT",
    body: JSON.stringify({
      private_key_enc: sealed.blob,
      kdf_salt: sealed.salt,
      kdf_params: JSON.stringify(KDF_PARAMS),
    }),
  });
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    throw new Error(j.error || "could not change the passphrase");
  }
}

/** Recovery: unseal with the code, reseal under a new passphrase, and issue a
 *  fresh code in the same step. A code that has been typed has been somewhere
 *  it can be read, so it does not survive its own use. */
export async function recoverWithCode(
  recoveryCode: string,
  newPassphrase: string
): Promise<string> {
  const res = await apiFetch("/vault/keyring?recovery=1");
  if (!res.ok) throw new Error("could not load your recovery key");
  const kr = await res.json();

  const pkcs8 = await unsealIdentity(
    recoveryCode,
    kr.recovery_key_enc,
    kr.recovery_salt,
    kr.fingerprint,
    kdfOf(kr)
  );
  const sealedPass = await reseal(pkcs8, kr.fingerprint, newPassphrase);
  const nextCode = (await import("./vault-crypto")).generateRecoveryCode();
  const sealedRec = await reseal(pkcs8, kr.fingerprint, nextCode);

  const save = await apiFetch("/vault/keyring", {
    method: "PUT",
    body: JSON.stringify({
      private_key_enc: sealedPass.blob,
      kdf_salt: sealedPass.salt,
      kdf_params: JSON.stringify(KDF_PARAMS),
      recovery_key_enc: sealedRec.blob,
      recovery_salt: sealedRec.salt,
      via_recovery: true,
    }),
  });
  if (!save.ok) {
    const j = await save.json().catch(() => ({}));
    throw new Error(j.error || "could not reset the passphrase");
  }
  return nextCode;
}

/** The vault key, unwrapped once per tab and kept for as long as the session
 *  is unlocked. Re-deriving it per item would mean an ECDH per row. */
export async function vaultKey(v: VaultSummary): Promise<CryptoKey> {
  if (!identity) throw new Error("locked");
  const cached = vaultKeys.get(v.uuid);
  if (cached) return cached;
  const key = await unwrapVaultKey(identity, v.wrapped_key, v.uuid, fingerprint);
  vaultKeys.set(v.uuid, key);
  return key;
}

/** Creates a vault by sealing a brand-new key to the creator's own public
 *  key. The key is generated here and never exists anywhere else unsealed. */
export async function createVault(opts: {
  name: string;
  description: string;
  kind: "personal" | "group";
  groupID?: number;
  myPublicKey: string;
}): Promise<string> {
  const uuid = crypto.randomUUID();
  const raw = newVaultKeyRaw();
  const wrapped = await wrapVaultKey(fromB64(opts.myPublicKey), raw, uuid, fingerprint);
  const res = await apiFetch("/vaults", {
    method: "POST",
    body: JSON.stringify({
      uuid,
      name: opts.name,
      description: opts.description,
      kind: opts.kind,
      group_id: opts.kind === "group" ? opts.groupID : undefined,
      wrapped_key: wrapped,
    }),
  });
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    throw new Error(j.error || "could not create the vault");
  }
  return uuid;
}

/** Shares a vault by resealing its key to somebody else's public key. The
 *  fingerprint is recomputed from the key that arrived rather than trusted
 *  from the response, so a substituted key at least produces a fingerprint
 *  that does not match the one the other person can read out to you. */
export async function shareVault(
  v: VaultSummary,
  recipient: { user_id: number; public_key: string; fingerprint: string },
  role: "writer" | "reader"
): Promise<void> {
  const spki = fromB64(recipient.public_key);
  const computed = await fingerprintOf(spki);
  if (computed !== recipient.fingerprint) {
    throw new Error("that public key does not match its fingerprint; do not share until this is explained");
  }
  // Unwrapped again rather than taken from the cache: the cached key is
  // non-extractable on purpose, and sharing is the one operation that
  // genuinely needs the bytes. They go out of scope with this call.
  if (!identity) throw new Error("locked");
  const raw = await unwrapVaultKeyRaw(identity, v.wrapped_key, v.uuid, fingerprint);
  const wrapped = await wrapVaultKey(spki, raw, v.uuid, computed);

  const res = await apiFetch(`/vaults/${v.uuid}/members`, {
    method: "POST",
    body: JSON.stringify({ user_id: recipient.user_id, role, wrapped_key: wrapped }),
  });
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    throw new Error(j.error || "could not share the vault");
  }
}
