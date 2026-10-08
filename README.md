# Lume Relay

The blind relay behind **Lume Remote**: it lets your paired devices reach each other from any network while
keeping everything end-to-end encrypted. Your history, files and approvals stay on your own computer (the Lume
Node). The Relay only forwards ciphertext, and it could not read it even if it wanted to.

Status: **prototype**. The wire protocol is versioned (`v1`) and may still change. It has not had the independent
security review that [Lume's threat model](https://github.com/Lume-agents/Lume/blob/main/docs/DISTRIBUTED_THREAT_MODEL.md)
requires before any public launch. Do not rely on it for sensitive work yet.

## How it works

- One **Durable Object per Node** (Cloudflare Workers, WebSocket Hibernation). Idle rooms cost almost nothing.
- The **room id is the fingerprint of the Node's Ed25519 public key** (hex SHA-256 of the raw key, the same value
  Lume reports). Nobody can claim another Node's room.
- Every connection proves possession of its key by signing a server challenge. A **client** is admitted only if the
  Node authorized its key, or if it presents a **pairing secret** the Node opened (single use, short-lived, stored
  only as a hash).
- Clients can talk **only to the Node**. The Node can talk to any authorized client.
- Frames for an offline peer wait in a **bounded queue** (200 frames, 1 MiB, 10 minutes, oldest dropped first) and
  are replayed when it reconnects.
- Limits: 256 KiB per frame, 16 peers per room, 60 frames per 10 seconds per connection, text frames only.
- Content encryption is done **by the peers** (the Relay has no session keys and does not parse `c`).

What the Relay can see: public keys and fingerprints, connection times, IP addresses (as any server does) and the
size of each ciphertext. It logs no content.

## Protocol (v1)

`GET /v1/rooms/<node-fingerprint>/connect` with a WebSocket upgrade, then JSON text frames:

| Direction | Frame |
|---|---|
| server → peer | `{"t":"challenge","v":1,"room":"…","nonce":"…"}` |
| peer → server | `{"t":"hello","role":"node"\|"client","publicKey":"<b64url 32 B>","signature":"<b64url 64 B>","pairing":"<secret, optional>"}` |
| server → peer | `{"t":"ready","role":"node"\|"client"\|"pairing","fingerprint":"…","node":"…"}` or `{"t":"error","code":"…"}` and close |
| peer → server | `{"t":"msg","id":"…","c":"<ciphertext>","to":"<client fingerprint, Node only>"}` |
| server → peer | `{"t":"msg","id":"…","from":"<fingerprint>","c":"…","replayed":true?}` |
| server → peer | `{"t":"presence","fingerprint":"…","role":"…","online":true\|false}` |
| Node → server | `{"t":"authorize","publicKey":"…"}`, `{"t":"revoke","fingerprint":"…"}`, `{"t":"open-pairing","hash":"…","ttl":300}` |

The signature covers `LUME-RELAY-V1\n<room>\n<nonce>\n<role>` and is verified with Ed25519.
`src/client.js` is a small reference client.

## Develop

```bash
npm install
npm test        # starts `wrangler dev` locally and runs the end-to-end tests
npm run dev     # local Relay at ws://127.0.0.1:8788
npm run deploy  # needs a Cloudflare account (Workers and Durable Objects)
```

## Self-hosting

Deploy it to your own Cloudflare account with `npm run deploy`. Lume Remote, the hosted service, runs this same code
plus a separate control plane (accounts, billing, push) that is not needed to self-host.

## License

[AGPL-3.0-or-later](./LICENSE). Contributions are welcome; a contributor agreement may be requested later so the
project can keep offering commercial licenses.
