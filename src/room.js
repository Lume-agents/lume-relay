// One Durable Object per Node. It authenticates peers, enforces who may talk to whom, forwards opaque
// ciphertext and keeps a small bounded queue for peers that are offline. It cannot read any message.
import { DurableObject } from "cloudflare:workers";
import { LIMITS, VERSION, b64u, fingerprint, isFingerprint, pairingHash, signedMessage, verifySignature } from "./protocol.js";

const json = (value) => JSON.stringify(value);

export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request) {
    const room = request.headers.get("x-lume-room");
    if (!isFingerprint(room)) return new Response("Bad room", { status: 400 });
    if (this.ctx.getWebSockets().length >= LIMITS.peersPerRoom) return new Response("Room is full", { status: 429 });
    const { 0: client, 1: server } = new WebSocketPair();
    this.ctx.acceptWebSocket(server);
    const nonce = b64u.encode(crypto.getRandomValues(new Uint8Array(32)));
    server.serializeAttachment({ state: "pending", room, nonce, tokens: LIMITS.rateFrames, last: Date.now() });
    server.send(json({ t: "challenge", v: VERSION, room, nonce }));
    return new Response(null, { status: 101, webSocket: client });
  }

  // ── helpers ────────────────────────────────────────────────────────────────
  fail(ws, code) {
    try { ws.send(json({ t: "error", code })); } catch { /* the peer is gone */ }
    try { ws.close(1008, code); } catch { /* already closed */ }
  }

  peers(fingerprintValue) {
    return this.ctx.getWebSockets().filter((socket) => {
      const attachment = socket.deserializeAttachment();
      return attachment?.state === "ready" && attachment.fingerprint === fingerprintValue;
    });
  }

  admit(ws, attachment, role, fingerprintValue) {
    ws.serializeAttachment({ ...attachment, state: "ready", role, fingerprint: fingerprintValue, nonce: undefined });
    ws.send(json({ t: "ready", role, fingerprint: fingerprintValue, node: attachment.room }));
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────
  async webSocketMessage(ws, message) {
    const attachment = ws.deserializeAttachment();
    if (!attachment) return this.fail(ws, "state");
    if (typeof message !== "string") return this.fail(ws, "text-only");
    if (message.length > LIMITS.frameBytes) return this.fail(ws, "too-large");
    const now = Date.now();
    const refill = ((now - attachment.last) / LIMITS.rateWindowMs) * LIMITS.rateFrames;
    const tokens = Math.min(LIMITS.rateFrames, attachment.tokens + refill) - 1;
    if (tokens < 0) return this.fail(ws, "rate-limited");
    attachment.tokens = tokens;
    attachment.last = now;
    ws.serializeAttachment(attachment);
    let frame;
    try { frame = JSON.parse(message); } catch { return this.fail(ws, "invalid"); }
    if (!frame || typeof frame.t !== "string") return this.fail(ws, "invalid");
    if (attachment.state === "pending") return this.hello(ws, attachment, frame);
    if (frame.t === "msg") return this.relay(ws, attachment, frame);
    if (attachment.role === "node") {
      if (frame.t === "authorize") return this.authorize(ws, attachment, frame);
      if (frame.t === "revoke") return this.revoke(attachment, frame);
      if (frame.t === "open-pairing") return this.openPairing(ws, frame);
    }
    return this.fail(ws, "unsupported");
  }

  async webSocketClose(ws, code) {
    const attachment = ws.deserializeAttachment();
    try { ws.close(code === 1005 ? 1000 : code, "bye"); } catch { /* already closed */ }
    if (attachment?.state === "ready") this.presence(attachment, false);
  }

  async webSocketError(ws) {
    const attachment = ws.deserializeAttachment();
    if (attachment?.state === "ready") this.presence(attachment, false);
  }

  presence(attachment, online) {
    const peers = attachment.role === "node"
      ? this.ctx.getWebSockets().filter((socket) => socket.deserializeAttachment()?.state === "ready" && socket.deserializeAttachment().role !== "node")
      : this.peers(attachment.room);
    for (const socket of peers) {
      try { socket.send(json({ t: "presence", fingerprint: attachment.fingerprint, role: attachment.role, online })); } catch { /* gone */ }
    }
  }

  // ── authentication ─────────────────────────────────────────────────────────
  async hello(ws, attachment, frame) {
    if (frame.t !== "hello") return this.fail(ws, "hello-expected");
    const role = frame.role;
    if (role !== "node" && role !== "client") return this.fail(ws, "role");
    let publicKey;
    let signature;
    try { publicKey = b64u.decode(String(frame.publicKey)); signature = b64u.decode(String(frame.signature)); } catch { return this.fail(ws, "encoding"); }
    if (publicKey.length !== 32 || signature.length !== 64) return this.fail(ws, "encoding");
    if (!(await verifySignature(publicKey, signature, signedMessage(attachment.room, attachment.nonce, role)))) return this.fail(ws, "bad-signature");
    const peer = await fingerprint(publicKey);

    if (role === "node") {
      if (peer !== attachment.room) return this.fail(ws, "not-the-node");
      for (const socket of this.peers(peer)) { try { socket.close(1000, "replaced"); } catch { /* ignore */ } }
      this.admit(ws, attachment, "node", peer);
      this.presence({ ...attachment, role: "node", fingerprint: peer }, true);
      await this.replay(ws, peer);
      return;
    }

    const known = await this.ctx.storage.get(`client:${peer}`);
    if (known) {
      this.admit(ws, attachment, "client", peer);
      this.presence({ ...attachment, role: "client", fingerprint: peer }, true);
      await this.replay(ws, peer);
      return;
    }
    if (typeof frame.pairing === "string" && (await this.consumePairing(frame.pairing))) {
      this.admit(ws, attachment, "pairing", peer);
      this.presence({ ...attachment, role: "pairing", fingerprint: peer }, true);
      return;
    }
    return this.fail(ws, "unauthorized");
  }

  // ── pairing and authorization (commands from the Node) ─────────────────────
  async openPairing(ws, frame) {
    const ttl = Math.min(Number(frame.ttl) || LIMITS.pairingTtlSeconds, LIMITS.pairingTtlSeconds);
    if (typeof frame.hash !== "string" || frame.hash.length < 20 || frame.hash.length > 64) return this.fail(ws, "invalid");
    const slots = await this.ctx.storage.list({ prefix: "pairing:" });
    const now = Date.now();
    let live = 0;
    for (const [key, slot] of slots) { if (slot.expiresAt < now) await this.ctx.storage.delete(key); else live += 1; }
    if (live >= LIMITS.pairingSlots) return this.fail(ws, "too-many-offers");
    await this.ctx.storage.put(`pairing:${frame.hash}`, { expiresAt: now + ttl * 1000, tries: 0 });
    ws.send(json({ t: "pairing-open", hash: frame.hash, expiresAt: now + ttl * 1000 }));
  }

  /** A pairing secret opens the door once. Only its hash is stored. */
  async consumePairing(secret) {
    if (secret.length < 16 || secret.length > 256) return false;
    const hash = await pairingHash(secret);
    const key = `pairing:${hash}`;
    const slot = await this.ctx.storage.get(key);
    if (!slot || slot.expiresAt < Date.now()) { if (slot) await this.ctx.storage.delete(key); return false; }
    await this.ctx.storage.delete(key);
    return true;
  }

  async authorize(ws, attachment, frame) {
    let publicKey;
    try { publicKey = b64u.decode(String(frame.publicKey)); } catch { return this.fail(ws, "encoding"); }
    if (publicKey.length !== 32) return this.fail(ws, "encoding");
    const peer = await fingerprint(publicKey);
    await this.ctx.storage.put(`client:${peer}`, { publicKey: frame.publicKey, addedAt: Date.now() });
    for (const socket of this.peers(peer)) {
      const current = socket.deserializeAttachment();
      socket.serializeAttachment({ ...current, role: "client" });
    }
    ws.send(json({ t: "authorized", fingerprint: peer }));
    await this.replayTo(peer);
  }

  async revoke(attachment, frame) {
    if (!isFingerprint(frame.fingerprint)) return;
    await this.ctx.storage.delete(`client:${frame.fingerprint}`);
    const queued = await this.ctx.storage.list({ prefix: `q:${frame.fingerprint}:` });
    await this.ctx.storage.delete([...queued.keys()]);
    for (const socket of this.peers(frame.fingerprint)) { try { socket.close(1008, "revoked"); } catch { /* ignore */ } }
  }

  // ── forwarding ─────────────────────────────────────────────────────────────
  async relay(ws, attachment, frame) {
    if (typeof frame.c !== "string" || typeof frame.id !== "string" || frame.id.length > 64) return this.fail(ws, "invalid");
    const toNode = attachment.role !== "node";
    const target = toNode ? attachment.room : frame.to;
    if (!isFingerprint(target)) return this.fail(ws, "recipient");
    if (!toNode && !(await this.ctx.storage.get(`client:${target}`))) return this.fail(ws, "unknown-recipient");
    const out = json({ t: "msg", id: frame.id, from: attachment.fingerprint, c: frame.c });
    const peers = this.peers(target);
    if (peers.length) { for (const socket of peers) { try { socket.send(out); } catch { /* gone */ } } return; }
    await this.enqueue(target, out);
  }

  async enqueue(target, payload) {
    const now = Date.now();
    const entries = await this.ctx.storage.list({ prefix: `q:${target}:` });
    let bytes = payload.length;
    const keep = [];
    for (const [key, value] of entries) {
      if (now - value.at > LIMITS.queueTtlMs) { await this.ctx.storage.delete(key); continue; }
      keep.push([key, value]);
      bytes += value.payload.length;
    }
    // Drop the oldest frames first when the bounded queue is full.
    while (keep.length && (keep.length >= LIMITS.queueFrames || bytes > LIMITS.queueBytes)) {
      const [key, value] = keep.shift();
      bytes -= value.payload.length;
      await this.ctx.storage.delete(key);
    }
    await this.ctx.storage.put(`q:${target}:${String(now).padStart(15, "0")}:${b64u.encode(crypto.getRandomValues(new Uint8Array(4)))}`, { at: now, payload });
  }

  async replay(ws, target) {
    const now = Date.now();
    const entries = await this.ctx.storage.list({ prefix: `q:${target}:` });
    const sent = [];
    for (const [key, value] of entries) {
      sent.push(key);
      if (now - value.at > LIMITS.queueTtlMs) continue;
      try { ws.send(value.payload.replace(/^\{/, '{"replayed":true,')); } catch { return; }
    }
    if (sent.length) await this.ctx.storage.delete(sent);
  }

  async replayTo(target) {
    for (const socket of this.peers(target)) await this.replay(socket, target);
  }
}
