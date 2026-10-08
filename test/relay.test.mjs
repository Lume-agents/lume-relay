import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { after, before, test } from "node:test";
import { connect, createIdentity } from "../src/client.js";
import { b64u, pairingHash } from "../src/protocol.js";

const port = 8791;
const base = `http://127.0.0.1:${port}`;
let server;

before(async () => {
  server = spawn("npx", ["wrangler", "dev", "--local", "--port", String(port), "--ip", "127.0.0.1"], { stdio: "ignore", env: { ...process.env, NO_COLOR: "1" } });
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try { if ((await fetch(`${base}/health`)).ok) return; } catch { /* still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("The Relay did not start");
});
after(() => { server?.kill("SIGTERM"); });

const secret = () => b64u.encode(crypto.getRandomValues(new Uint8Array(24)));
const msg = (id, c, to) => ({ t: "msg", id, c, ...(to ? { to } : {}) });
async function newNode() { const identity = await createIdentity(); const { peer, answer } = await connect(base, identity.fingerprint, identity, "node"); assert.equal(answer.t, "ready"); return { identity, peer }; }

test("the room belongs to the Node's key: nobody else can claim it", async () => {
  const node = await createIdentity();
  const intruder = await createIdentity();
  const { answer } = await connect(base, node.fingerprint, intruder, "node");
  assert.deepEqual([answer.t, answer.code], ["error", "not-the-node"]);
  const real = await connect(base, node.fingerprint, node, "node");
  assert.equal(real.answer.role, "node");
  real.peer.close();
});

test("an unknown client is refused", async () => {
  const { identity, peer } = await newNode();
  const client = await createIdentity();
  const { answer } = await connect(base, identity.fingerprint, client, "client");
  assert.equal(answer.code, "unauthorized");
  peer.close();
});

test("an authorized client and the Node exchange ciphertext both ways", async () => {
  const { identity, peer: node } = await newNode();
  const client = await createIdentity();
  node.send({ t: "authorize", publicKey: client.publicKeyText });
  await node.next((f) => f.t === "authorized");
  const joined = await connect(base, identity.fingerprint, client, "client");
  assert.equal(joined.answer.role, "client");
  await node.next((f) => f.t === "presence" && f.online && f.fingerprint === client.fingerprint);
  joined.peer.send(msg("1", "Y2lwaGVydGV4dC1hbg"));
  const received = await node.next((f) => f.t === "msg");
  assert.deepEqual([received.from, received.c, received.id], [client.fingerprint, "Y2lwaGVydGV4dC1hbg", "1"]);
  node.send(msg("2", "cmVwbHk", client.fingerprint));
  const reply = await joined.peer.next((f) => f.t === "msg");
  assert.deepEqual([reply.from, reply.c], [identity.fingerprint, "cmVwbHk"]);
  node.close(); joined.peer.close();
});

test("a client can only talk to the Node, never to another client", async () => {
  const { identity, peer: node } = await newNode();
  const one = await createIdentity();
  const two = await createIdentity();
  for (const client of [one, two]) { node.send({ t: "authorize", publicKey: client.publicKeyText }); await node.next((f) => f.t === "authorized"); }
  const first = await connect(base, identity.fingerprint, one, "client");
  const second = await connect(base, identity.fingerprint, two, "client");
  first.peer.send(msg("x", "c2VjcmV0", two.fingerprint));
  await assert.rejects(second.peer.next((f) => f.t === "msg", 700));
  const forwarded = await node.next((f) => f.t === "msg");
  assert.equal(forwarded.from, one.fingerprint);
  node.close(); first.peer.close(); second.peer.close();
});

test("frames for an offline peer are queued and replayed when it returns", async () => {
  const { identity, peer: node } = await newNode();
  const client = await createIdentity();
  node.send({ t: "authorize", publicKey: client.publicKeyText });
  await node.next((f) => f.t === "authorized");
  node.send(msg("q1", "b25l", client.fingerprint));
  node.send(msg("q2", "dHdv", client.fingerprint));
  await new Promise((resolve) => setTimeout(resolve, 300));
  const joined = await connect(base, identity.fingerprint, client, "client");
  const first = await joined.peer.next((f) => f.t === "msg");
  const second = await joined.peer.next((f) => f.t === "msg");
  assert.deepEqual([first.id, first.replayed, second.id], ["q1", true, "q2"]);
  node.close(); joined.peer.close();
});

test("revoking a client disconnects it and removes its access", async () => {
  const { identity, peer: node } = await newNode();
  const client = await createIdentity();
  node.send({ t: "authorize", publicKey: client.publicKeyText });
  await node.next((f) => f.t === "authorized");
  const joined = await connect(base, identity.fingerprint, client, "client");
  node.send({ t: "revoke", fingerprint: client.fingerprint });
  assert.equal((await joined.peer.closed).reason, "revoked");
  assert.equal((await connect(base, identity.fingerprint, client, "client")).answer.code, "unauthorized");
  node.close();
});

test("a pairing secret admits a new device exactly once, and only its hash is stored", async () => {
  const { identity, peer: node } = await newNode();
  const offer = secret();
  node.send({ t: "open-pairing", hash: await pairingHash(offer), ttl: 60 });
  await node.next((f) => f.t === "pairing-open");
  const wrong = await connect(base, identity.fingerprint, await createIdentity(), "client", { pairing: secret() });
  assert.equal(wrong.answer.code, "unauthorized");
  const device = await createIdentity();
  const admitted = await connect(base, identity.fingerprint, device, "client", { pairing: offer });
  assert.equal(admitted.answer.role, "pairing");
  admitted.peer.send(msg("hello", "cGFpcg"));
  assert.equal((await node.next((f) => f.t === "msg")).from, device.fingerprint);
  const reuse = await connect(base, identity.fingerprint, await createIdentity(), "client", { pairing: offer });
  assert.equal(reuse.answer.code, "unauthorized");
  node.close(); admitted.peer.close();
});

test("limits: oversized frames, binary frames and malformed input are rejected", async () => {
  const { identity, peer: node } = await newNode();
  const client = await createIdentity();
  node.send({ t: "authorize", publicKey: client.publicKeyText });
  await node.next((f) => f.t === "authorized");
  const big = await connect(base, identity.fingerprint, client, "client");
  big.peer.socket.send("x".repeat(300 * 1024));
  assert.equal((await big.peer.closed).reason, "too-large");
  const raw = await connect(base, identity.fingerprint, client, "client");
  raw.peer.socket.send("not json");
  assert.equal((await raw.peer.closed).reason, "invalid");
  const bin = await connect(base, identity.fingerprint, client, "client");
  bin.peer.socket.send(new Uint8Array([1, 2, 3]));
  assert.equal((await bin.peer.closed).reason, "text-only");
  node.close();
});

test("a peer that floods the Relay is disconnected", async () => {
  const { identity, peer: node } = await newNode();
  const client = await createIdentity();
  node.send({ t: "authorize", publicKey: client.publicKeyText });
  await node.next((f) => f.t === "authorized");
  const flood = await connect(base, identity.fingerprint, client, "client");
  for (let index = 0; index < 100; index += 1) flood.peer.send(msg(`f${index}`, "Zmxvb2Q"));
  assert.equal((await flood.peer.closed).reason, "rate-limited");
  node.close();
});
