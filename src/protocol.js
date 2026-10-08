// Wire format of the Lume Relay, version 1. The Relay never sees plaintext: `c` is opaque ciphertext.
export const VERSION = 1;
export const SIGNATURE_DOMAIN = "LUME-RELAY-V1";
export const LIMITS = {
  frameBytes: 256 * 1024,
  peersPerRoom: 16,
  pairingSlots: 3,
  pairingTtlSeconds: 300,
  pairingTries: 5,
  queueFrames: 200,
  queueBytes: 1024 * 1024,
  queueTtlMs: 10 * 60 * 1000,
  rateFrames: 60,
  rateWindowMs: 10_000,
};

const encoder = new TextEncoder();

export const b64u = {
  encode(bytes) {
    let text = "";
    for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
    const text = atob(padded);
    return Uint8Array.from(text, (character) => character.charCodeAt(0));
  },
};

/** Hex SHA-256 of the raw public key: the same fingerprint the Lume Node reports. */
export async function fingerprint(publicKey) {
  const digest = await crypto.subtle.digest("SHA-256", publicKey);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export const isFingerprint = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);

export function signedMessage(room, nonce, role) {
  return encoder.encode(`${SIGNATURE_DOMAIN}\n${room}\n${nonce}\n${role}`);
}

export async function verifySignature(publicKey, signature, message) {
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
  } catch {
    return false;
  }
}

/** The secret a pairing offer carries is stored by the Relay only as this hash. */
export async function pairingHash(secret) {
  return b64u.encode(await crypto.subtle.digest("SHA-256", encoder.encode(secret)));
}
