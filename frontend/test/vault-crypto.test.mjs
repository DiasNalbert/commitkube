/** The vault's cryptographic properties, exercised for real.
 *
 *  Typechecking proves these functions compose; it does not prove that a
 *  ciphertext lifted from one item fails to open as another, which is the
 *  actual claim the feature makes. Run with: npm run test:crypto
 *
 *  It runs against the compiled module rather than the source, so what is
 *  tested is what ships.
 */

import {
  enrol, unlockIdentity, unsealIdentity, fingerprintOf, fromB64, toB64,
  newVaultKeyRaw, wrapVaultKey, unwrapVaultKey, unwrapVaultKeyRaw,
  sealOverview, openOverview, sealSecret, openSecret,
  generatePassword, generateRecoveryCode, normaliseRecoveryCode,
} from "../.crypto-test/vault-crypto.js";

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; console.log("  ok   " + name); } else { fail++; console.log("  FAIL " + name); } };
const throws = async (name, fn) => {
  try { await fn(); fail++; console.log("  FAIL " + name + " (did not throw)"); }
  catch { pass++; console.log("  ok   " + name); }
};

console.log("\n-- identity --");
const alice = await enrol("correct horse battery staple 42");
ok("fingerprint is a sha-256 hex digest", /^[0-9a-f]{64}$/.test(alice.fingerprint));
ok("fingerprint matches the public key", alice.fingerprint === await fingerprintOf(fromB64(alice.publicKey)));
await unlockIdentity("correct horse battery staple 42", alice.privateKeyEnc, alice.kdfSalt, alice.fingerprint);
ok("the right passphrase unlocks", true);
await throws("a wrong passphrase does not", () =>
  unlockIdentity("correct horse battery staple 43", alice.privateKeyEnc, alice.kdfSalt, alice.fingerprint));
await throws("a blob rebound to another identity does not open", () =>
  unlockIdentity("correct horse battery staple 42", alice.privateKeyEnc, alice.kdfSalt, "0".repeat(64)));

console.log("\n-- recovery --");
await unsealIdentity(alice.recoveryCode, alice.recoveryKeyEnc, alice.recoverySalt, alice.fingerprint);
ok("the recovery code opens the same identity", true);
ok("recovery code is crockford base32, grouped", /^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){7}$/.test(alice.recoveryCode));
ok("normalising a typed code is idempotent", normaliseRecoveryCode(alice.recoveryCode.toLowerCase()) === alice.recoveryCode);

console.log("\n-- vault keys --");
const vaultA = crypto.randomUUID(), vaultB = crypto.randomUUID();
const rawA = newVaultKeyRaw();
const aliceKey = await unlockIdentity("correct horse battery staple 42", alice.privateKeyEnc, alice.kdfSalt, alice.fingerprint);
const wrappedForAlice = await wrapVaultKey(fromB64(alice.publicKey), rawA, vaultA, alice.fingerprint);
const backRaw = await unwrapVaultKeyRaw(aliceKey, wrappedForAlice, vaultA, alice.fingerprint);
ok("a wrapped vault key round-trips to the same bytes", toB64(backRaw) === toB64(rawA));
await throws("the same wrapped key will not open as another vault", () =>
  unwrapVaultKeyRaw(aliceKey, wrappedForAlice, vaultB, alice.fingerprint));
await throws("nor under a different recipient fingerprint", () =>
  unwrapVaultKeyRaw(aliceKey, wrappedForAlice, vaultA, "1".repeat(64)));

console.log("\n-- items --");
const keyA = await unwrapVaultKey(aliceKey, wrappedForAlice, vaultA, alice.fingerprint);
const itemID = crypto.randomUUID(), otherID = crypto.randomUUID();
const ovBlob = await sealOverview(keyA, vaultA, itemID, { name: "prod postgres", username: "svc_api" });
const secBlob = await sealSecret(keyA, vaultA, itemID, { password: "hunter2", notes: "rotate quarterly" });
const ov = await openOverview(keyA, vaultA, itemID, ovBlob);
const sec = await openSecret(keyA, vaultA, itemID, secBlob);
ok("overview round-trips", ov.name === "prod postgres" && ov.username === "svc_api");
ok("secret round-trips", sec.password === "hunter2" && sec.notes === "rotate quarterly");
await throws("a blob moved to another item will not open", () => openSecret(keyA, vaultA, otherID, secBlob));
await throws("a blob moved to another vault will not open", () => openSecret(keyA, vaultB, itemID, secBlob));
await throws("the overview half will not open as the secret half", () => openSecret(keyA, vaultA, itemID, ovBlob));

console.log("\n-- padding --");
const short = await sealSecret(keyA, vaultA, itemID, { password: "a" });
const long = await sealSecret(keyA, vaultA, itemID, { password: "a".repeat(60) });
ok("a 1-char and a 60-char password seal to the same length", short.length === long.length);
const huge = await sealSecret(keyA, vaultA, itemID, { password: "a".repeat(400) });
ok("a much longer secret does grow (padding is bounded, not fixed)", huge.length > short.length);
ok("padded content still round-trips exactly",
  (await openSecret(keyA, vaultA, itemID, huge)).password === "a".repeat(400));

console.log("\n-- sharing --");
const bob = await enrol("a different passphrase entirely!!");
const bobKey = await unlockIdentity("a different passphrase entirely!!", bob.privateKeyEnc, bob.kdfSalt, bob.fingerprint);
const wrappedForBob = await wrapVaultKey(fromB64(bob.publicKey), rawA, vaultA, bob.fingerprint);
const bobVaultKey = await unwrapVaultKey(bobKey, wrappedForBob, vaultA, bob.fingerprint);
const bobSees = await openSecret(bobVaultKey, vaultA, itemID, secBlob);
ok("a shared member opens the owner's item", bobSees.password === "hunter2");
await throws("the owner's own wrapped key is useless to the member", () =>
  unwrapVaultKey(bobKey, wrappedForAlice, vaultA, alice.fingerprint));
const mallory = await enrol("mallory's passphrase goes here");
const malloryKey = await unlockIdentity("mallory's passphrase goes here", mallory.privateKeyEnc, mallory.kdfSalt, mallory.fingerprint);
await throws("a non-member cannot unwrap a key sealed to someone else", () =>
  unwrapVaultKey(malloryKey, wrappedForBob, vaultA, bob.fingerprint));

console.log("\n-- generator --");
const pw = generatePassword(32);
ok("generated password has the requested length", pw.length === 32);
ok("two generated passwords differ", generatePassword(32) !== generatePassword(32));
const codes = new Set(Array.from({ length: 50 }, () => generateRecoveryCode()));
ok("recovery codes do not repeat", codes.size === 50);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
