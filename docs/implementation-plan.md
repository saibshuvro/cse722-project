# CSE722 Encrypted Chat Application Plan

## 1. Summary

Build a greenfield TypeScript/Node.js application that runs directly on both Ubuntu and Kali. Each instance provides a minimal browser GUI while its local backend communicates directly with the other machine through raw TCP.

The application will enforce the required demonstration sequence:

1. Connect using the peer's IP address.
2. Exchange at least one plaintext message in each direction.
3. Exchange RSA public identity keys using an **Exchange Public Keys** button.
4. Manually verify both SHA-256 fingerprints out of band.
5. Transfer a fresh AES-256 session key using a **Start Secure Session** button.
6. Exchange AES-GCM-encrypted messages.

Vercel, Docker, databases, group chat, persistent message history, the final report, and viva materials are outside this implementation scope.

## 2. Architecture and User Flow

### 2.1 Technology and processes

- Use Node.js 22 or newer, TypeScript, npm, Express, `ws`, Zod, and Node's built-in `net`, `crypto`, and filesystem APIs.
- Serve a vanilla HTML/CSS/JavaScript interface at `http://localhost:3000`; avoid React, external CDNs, and a frontend build framework.
- Bind the GUI server to `127.0.0.1:3000` and the peer TCP listener to `0.0.0.0:5050`.
- Both instances always listen for incoming TCP connections and can initiate an outgoing connection by IP address.
- Each application instance supports one active peer and one secure session at a time. Ubuntu and Kali can exchange any number of bidirectional messages, but group chat and simultaneous conversations with additional clients are excluded.
- Use `172.16.217.1` for Ubuntu and `172.16.217.130` for Kali during the current demonstration, but never hard-code either address.
- Resolve simultaneous connection attempts using persisted installation IDs: retain the connection with the lexicographically smallest `(dialerInstallationId, connectionId)` tuple and close the duplicate consistently at both ends.

### 2.2 Application state

Implement these application states:

```text
DISCONNECTED
  -> CONNECTED_CLEAR
  -> CLEAR_EXCHANGED
  -> KEYS_UNVERIFIED
  -> IDENTITY_VERIFIED
  -> SECURE_NEGOTIATING
  -> SECURE_ACTIVE
```

- Require one plaintext message in each direction before enabling **Exchange Public Keys**.
- Permit plaintext messaging until secure negotiation starts.
- Enable **Start Secure Session** only after both users have confirmed fingerprints.
- After `SECURE_ACTIVE`, send all chat messages as encrypted messages.
- On disconnect, erase the AES key and all session state while retaining the long-term identity key.

### 2.3 Minimal GUI

Create one responsive page containing:

- Connection status, peer-IP input, **Connect**, and **Disconnect** controls.
- A required-steps checklist showing the current protocol stage.
- Chat transcript with a visible `PLAINTEXT` or `ENCRYPTED` badge on every message.
- Local fingerprint with Show/Hide and Copy controls.
- An **Exchange Public Keys** button and the received peer fingerprint.
- Explicit **Fingerprints match** and **Reject fingerprint** actions.
- A **Start Secure Session** button.
- A timestamped security/event log showing verification results without revealing secret material.

## 3. Cryptographic Protocol and Interfaces

### 3.1 Identity generation and persistence

- Generate one RSA-3072 key pair per installation on first launch, using public exponent 65537.
- Store the private key as PKCS#8 PEM and the public key as SPKI PEM under `~/.local/share/cse722-chat/`.
- Store a random installation UUID beside the key pair.
- Set the data directory to mode `0700` and the private-key file to `0600`.
- Write keys atomically. If stored keys are corrupt or mismatched, fail with an actionable error and never silently replace them.
- Reuse the same identity after restarts, but never persist AES session keys.
- Calculate the fingerprint as SHA-256 over canonical SPKI DER bytes, formatted as uppercase colon-separated hexadecimal.
- Use the RSA pair for RSA-PSS signatures and RSA-OAEP key wrapping. This assignment-aligned simplification should be documented; separate signing and encryption keys or authenticated ephemeral Diffie-Hellman can be discussed later as alternatives.

### 3.2 Peer TCP framing

Use UTF-8 newline-delimited JSON over raw TCP. Each frame contains protocol version `1`, a frame type, and a connection ID.

- Enforce a 64 KiB maximum frame size.
- Correctly handle partial frames and multiple frames arriving in one TCP read.
- Validate every incoming frame with Zod before processing it.
- Encode signatures, ciphertext, tags, and wrapped keys as Base64.
- Include an `algorithm` field in cryptographic frames so Wireshark visibly identifies `RSA-OAEP-SHA256`, `RSA-PSS-SHA256`, or `AES-256-GCM` without exposing plaintext.

Peer frame types:

- `hello` / `hello_ack`: protocol version, installation ID, connection ID, and dialer ID.
- `clear_message`: plaintext, message ID, and timestamp. Its `text` field must be directly visible in Wireshark.
- `identity_request` / `identity_key`: initiate mutual public-key exchange and carry SPKI PEM.
- `fingerprint_verified`: signed notice that the sender manually verified the recipient's fingerprint.
- `key_offer`: RSA-OAEP-wrapped AES key and RSA-PSS signature.
- `key_confirm` / `secure_ready`: AES-GCM-protected two-way key-possession confirmation.
- `secure_message`: `algorithm: "AES-256-GCM"`, sequence number, Base64 ciphertext, and authentication tag. The original message text must not be present in the frame.
- `protocol_error` / `goodbye`: controlled failure and shutdown.

Example capture-visible plaintext frame:

```json
{
  "v": 1,
  "type": "clear_message",
  "text": "This is a plaintext test"
}
```

Example capture-visible encrypted frame shape:

```json
{
  "v": 1,
  "type": "secure_message",
  "algorithm": "AES-256-GCM",
  "sequence": 1,
  "ciphertext": "BASE64_CIPHERTEXT",
  "authTag": "BASE64_AUTHENTICATION_TAG"
}
```

### 3.3 Mutual fingerprint verification

- Pressing **Exchange Public Keys** sends the initiator's public key and requests the peer's key; the recipient automatically responds with its public key.
- Each receiver imports the key and independently computes its fingerprint instead of trusting a transmitted fingerprint.
- Both users compare fingerprints out of band and press **Fingerprints match**.
- Each confirmation sends an RSA-PSS/SHA-256 signed fixed-order payload:

```text
[1, "fingerprint_verified", connectionId,
 senderFingerprint, recipientFingerprint]
```

- Enter `IDENTITY_VERIFIED` only after the local user verifies the peer and a valid signed notice confirms that the peer verified the local fingerprint.
- Rejecting a fingerprint, receiving a changed key, or receiving an invalid confirmation disconnects the session.

### 3.4 Authenticated AES-key transfer

- Either verified client can press **Start Secure Session**.
- The initiator generates a fresh random 32-byte AES-256 key and a random 128-bit session ID.
- Encrypt the AES key with the recipient's RSA public key using RSA-OAEP with SHA-256.
- Sign the fixed-order key-offer payload using RSA-PSS/SHA-256 with a 32-byte salt:

```text
[1, "key_offer", connectionId, sessionId,
 senderFingerprint, recipientFingerprint, wrappedKeyBase64]
```

- The recipient checks connection/session binding, fingerprints, signature, and OAEP decryption in that order.
- The recipient sends an AES-GCM `key_confirm`; the initiator decrypts it and replies with AES-GCM `secure_ready`.
- Only after this round trip do both clients enter `SECURE_ACTIVE`.
- Log visible results for recipient binding, RSA signature validation, AES-key decryption, and key-possession confirmation.

### 3.5 Encrypted messages

- Use AES-256-GCM with a 16-byte authentication tag.
- Use sequence `0` for confirmation frames and start chat messages at sequence `1` independently in each direction.
- Construct each 12-byte GCM nonce from:
  - The first four bytes of SHA-256 over the protocol domain, session ID, and sender fingerprint.
  - An eight-byte unsigned big-endian sequence number.
- Authenticate this fixed-order metadata as GCM additional authenticated data:

```text
[1, frameType, connectionId, sessionId, senderFingerprint, sequence]
```

- Encrypt the message text, message ID, and timestamp together.
- Require the next exact sequence number and reject replayed or out-of-order frames.
- On signature, GCM, replay, protocol-version, or schema failure, log a red security event, erase the in-memory session key, and disconnect instead of falling back to plaintext.

### 3.6 Browser/backend control interface

Use a same-origin WebSocket endpoint at `/control`.

Browser commands:

- `connect { peerIp }`
- `disconnect`
- `send_message { text }`
- `exchange_keys`
- `verify_fingerprint { decision: "accept" | "reject" }`
- `start_secure_session`

Backend events:

- `state`: authoritative protocol state, fingerprints, peer IP, and permitted actions.
- `chat_message`: direction, security mode, timestamp, and text.
- `security_event`: timestamp, severity, and sanitized explanation.
- `error`: recoverable UI or input error.

Validate IPv4 input, trim messages, reject empty messages, and limit chat content to 2,000 UTF-8 bytes.

## 4. Implementation Phases

### Phase 1 — Project foundation

- Configure the existing repository as an npm/TypeScript project.
- Add Express, WebSocket, Zod, Vitest, and TypeScript tooling.
- Create environment-based port and data-directory configuration.
- Add the minimal static GUI, local control WebSocket, and health endpoint.
- Add build, start, development, type-check, and test scripts.

**Completion gate:** The project installs, type-checks, tests, builds, starts, and opens at `http://localhost:3000`.

### Phase 2 — TCP connection and plaintext chat

- Add the TCP listener, peer-IP connection, disconnect behavior, and protocol greeting.
- Implement validated NDJSON framing and plaintext messaging.
- Display incoming and outgoing messages with `PLAINTEXT` badges and connection events.

**Completion gate:** Ubuntu and Kali exchange plaintext messages in both directions and the message text is visible in Wireshark.

### Phase 3 — Persistent identity

- Generate, validate, and persist the RSA-3072 identity and installation ID.
- Derive and display the SHA-256 public-key fingerprint.
- Test key permissions, persistence, corruption handling, and stable fingerprints.

**Completion gate:** Each machine has a different fingerprint that remains unchanged after restart.

### Phase 4 — Public-key exchange and verification

- Implement public-key request/response frames and the **Exchange Public Keys** button.
- Display the computed peer fingerprint and add accept/reject controls.
- Exchange signed verification notices and require confirmation by both users.

**Completion gate:** Both clients reach `IDENTITY_VERIFIED`; rejected or invalid fingerprints terminate the session safely.

### Phase 5 — Authenticated AES-key transfer

- Add the **Start Secure Session** button and generate a fresh AES-256 key.
- Wrap the key with RSA-OAEP, sign the envelope with RSA-PSS, and verify both operations.
- Complete AES-GCM `key_confirm` / `secure_ready` key-possession confirmation.

**Completion gate:** Both clients reach `SECURE_ACTIVE` and the event log shows each authenticity check.

### Phase 6 — Encrypted chat and defensive behavior

- Implement AES-256-GCM messages, deterministic nonces, authenticated metadata, and sequences.
- Add `ENCRYPTED` badges and capture-visible algorithm/ciphertext fields.
- Reject tampering, replay, invalid ordering, and attempted plaintext downgrade.

**Completion gate:** Encrypted messages work in both directions, while Wireshark cannot find the original message text.

### Phase 7 — Integration and demonstration readiness

- Complete two-process integration, restart, malformed-frame, duplicate-connection, and busy-peer tests.
- Run the full Ubuntu/Kali workflow and finish installation and troubleshooting documentation.
- Capture the required plaintext and encrypted Wireshark evidence.

**Completion gate:** A clean clone can be installed and demonstrated by following the README, and all automated checks pass.

Tests should be implemented alongside each phase rather than deferred to Phase 7.

## 5. Implementation and Deliverables

- Use the existing Git repository and configured GitHub remote; do not replace or reinitialize them.
- Configure the repository as an npm TypeScript project while preserving the already tracked assignment PDF.
- Organize backend code under `src/`, static GUI assets under `public/`, and automated tests under `tests/`.
- Provide scripts for `dev`, `build`, `start`, `typecheck`, and `test`; commit `package-lock.json`.
- Support configuration through:
  - `WEB_PORT`, default `3000`
  - `CHAT_PORT`, default `5050`
  - `CHAT_BIND_ADDRESS`, default `0.0.0.0`
  - `DATA_DIR`, default `~/.local/share/cse722-chat`
- Never log private keys, AES keys, decrypted key offers, decrypted secure messages in the security log, or authentication tags.
- Add `.gitignore` coverage for dependencies, builds, logs, local key material, and test artifacts.
- Add a README containing Ubuntu/Kali prerequisites, Kali Node.js installation, installation/build/run commands, firewall troubleshooting, first-launch key behavior, and the complete two-machine demonstration sequence.
- Do not push changes unless the user explicitly requests it.

## 6. Test and Acceptance Plan

### 6.1 Automated tests

Test the following:

- Identity generation, restrictive permissions, persistence, reload, and deterministic fingerprinting.
- RSA-OAEP wrap/unwrap and RSA-PSS sign/verify, including altered-envelope failures.
- AES-GCM round trips, nonce construction, tampered ciphertext/tag rejection, replay rejection, and sequence enforcement.
- NDJSON fragmentation, multiple frames per read, malformed JSON, oversized frames, and schema rejection.
- State-machine gating for clear messages, key exchange, fingerprint confirmation, and secure mode.
- A two-process integration flow using separate temporary data directories and alternate ports:
  plaintext exchange -> key exchange -> mutual verification -> AES transfer -> encrypted reply.
- Restart behavior: identity remains unchanged while the previous AES session disappears.
- Duplicate/simultaneous connection resolution and busy rejection for a third client.
- `npm run typecheck`, `npm test`, and `npm run build` must all pass.

### 6.2 Manual Ubuntu/Kali acceptance

1. Confirm both applications display different persistent identity fingerprints.
2. Confirm either machine can initiate the TCP connection.
3. Exchange a plaintext message and reply.
4. Press **Exchange Public Keys** and confirm both fingerprints out of band.
5. Press **Start Secure Session** from either verified client.
6. Confirm the event log reports successful authenticity and key-possession checks.
7. Exchange encrypted messages in both directions and confirm their GUI badges read `ENCRYPTED`.
8. Capture on Kali `eth0`, Ubuntu `vmnet8`, or both, using the display filter `tcp.port == 5050`.
9. Confirm the clear frame exposes the test text while the secure frame visibly identifies AES-256-GCM and contains only ciphertext/tag data.
10. Disconnect and confirm the secure-session state is erased; reconnecting must require fingerprint confirmation and a fresh AES key.

Only one Wireshark capture location is required for the report. Because Wireshark is already installed on Kali, capturing `eth0` there is sufficient; Ubuntu capture support remains optional.

## 7. Assumptions and Defaults

- Ubuntu and Kali remain reachable through VMware NAT at their current addresses; DHCP addresses will be rechecked before demonstrations.
- Node.js 22 or newer will be installed on Kali before implementation testing.
- Wireshark may run on Kali, Ubuntu, or both; Kali `eth0` is the current default capture interface.
- The same source tree runs on both machines; each installation generates its own identity outside the repository.
- Local private-key protection relies on Linux file permissions and the user account; passphrase-encrypted keys are outside scope.
- One active conversation with one peer is supported, with no accounts, cloud relay, message history, file transfer, reconnection recovery, or internet deployment.
