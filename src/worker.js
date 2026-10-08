// Lume Relay: routes each WebSocket to the Durable Object of its room.
// The room id is the fingerprint of the Node's public key, so nobody can claim another Node's room.
import { Room } from "./room.js";
import { isFingerprint } from "./protocol.js";

export { Room };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") return new Response("ok", { headers: { "cache-control": "no-store" } });
    const match = /^\/v1\/rooms\/([0-9a-f]{64})\/connect$/.exec(url.pathname);
    if (!match || !isFingerprint(match[1])) return new Response("Not found", { status: 404 });
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return new Response("Expected a WebSocket", { status: 426 });
    const stub = env.ROOMS.get(env.ROOMS.idFromName(match[1]));
    const forwarded = new Request(request);
    forwarded.headers.set("x-lume-room", match[1]);
    return stub.fetch(forwarded);
  },
};
