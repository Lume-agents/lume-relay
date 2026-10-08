// A small reference client for the Relay protocol, used by the tests and as a guide for the Node transport.
import { b64u, fingerprint, signedMessage } from "./protocol.js";

export async function createIdentity() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicKey, publicKeyText: b64u.encode(publicKey), fingerprint: await fingerprint(publicKey) };
}

export class Peer {
  constructor(socket) {
    this.socket = socket;
    this.frames = [];
    this.waiting = [];
    this.closed = new Promise((resolve) => socket.addEventListener("close", (event) => resolve({ code: event.code, reason: event.reason })));
    socket.addEventListener("message", (event) => {
      const frame = JSON.parse(event.data);
      const index = this.waiting.findIndex((waiter) => waiter.test(frame));
      if (index >= 0) this.waiting.splice(index, 1)[0].resolve(frame);
      else this.frames.push(frame);
    });
  }

  send(frame) { this.socket.send(JSON.stringify(frame)); }

  /** Resolves with the next frame matching `test` (already received frames count). */
  next(test = () => true, timeout = 4000) {
    const index = this.frames.findIndex(test);
    if (index >= 0) return Promise.resolve(this.frames.splice(index, 1)[0]);
    return new Promise((resolve, reject) => {
      const waiter = { test, resolve };
      this.waiting.push(waiter);
      setTimeout(() => { this.waiting = this.waiting.filter((item) => item !== waiter); reject(new Error("Timed out waiting for a frame")); }, timeout);
    });
  }

  close() { try { this.socket.close(1000); } catch { /* closed */ } }
}

/** Opens a connection and performs the signed hello. Resolves with the peer and the server's first answer. */
export async function connect(baseUrl, room, identity, role, extra = {}) {
  const socket = new WebSocket(`${baseUrl.replace(/^http/, "ws")}/v1/rooms/${room}/connect`);
  const peer = new Peer(socket);
  await new Promise((resolve, reject) => { socket.addEventListener("open", resolve); socket.addEventListener("error", () => reject(new Error("connection failed"))); });
  const challenge = await peer.next((frame) => frame.t === "challenge");
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, identity.privateKey, signedMessage(room, challenge.nonce, role)));
  peer.send({ t: "hello", role, publicKey: identity.publicKeyText, signature: b64u.encode(signature), ...extra });
  const answer = await peer.next((frame) => frame.t === "ready" || frame.t === "error");
  return { peer, answer };
}
