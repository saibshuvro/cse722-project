# CSE722 Encrypted Chat

A two-peer chat application for demonstrating plaintext communication, manual identity-key verification, authenticated AES-256 key transfer, and AES-256-GCM encrypted messaging.

Phase 7 completes the demonstration-ready application: direct TCP plaintext chat, persistent RSA-3072 identities, mutual out-of-band fingerprint verification, authenticated AES-256 session-key transfer, AES-256-GCM encrypted messaging, defensive protocol handling, and end-to-end integration coverage.

## Requirements

- Node.js 22 or newer
- npm
- Two mutually reachable machines or virtual machines

On Kali, install the runtime if needed:

```bash
sudo apt update
sudo apt install -y nodejs npm
node --version
npm --version
```

## Clean installation and verification

Clone or copy the same project to both machines, then run on each:

```bash
npm ci
npm run typecheck
npm test
npm run build
npm start
```

Open <http://localhost:3000> in each machine's browser. Both applications listen for peer TCP connections on port `5050`.

For development, use:

```bash
npm run dev
```

## Complete two-machine demonstration

Current VMware NAT addresses:

- Ubuntu host (`vmnet8`): `172.16.217.1`
- Kali VM (`eth0`): `172.16.217.130`

1. Start the application on Ubuntu and Kali.
2. On one machine only, enter the other machine's IPv4 address and select **Connect**.
3. Send a unique plaintext message and reply from the other machine.
4. Confirm both interfaces show `CLEAR_EXCHANGED` and both messages have `PLAINTEXT` badges.
5. Select **Exchange Public Keys** on either machine.
6. Display the local fingerprint on each machine and compare it with the peer fingerprint shown on the other machine.
7. If both comparisons match exactly, select **Fingerprints match** on both machines.
8. Confirm both interfaces reach `IDENTITY_VERIFIED`.
9. Select **Start Secure Session** on either machine and confirm both reach `SECURE_ACTIVE`.
10. Send a new, unique message in each direction and confirm both messages have `ENCRYPTED` badges.
11. Disconnect and confirm both return to `DISCONNECTED`.
12. Reconnect and confirm identity fingerprints remain stable while fingerprint verification and a fresh secure session are required again.

Either client may initiate the connection or secure session. If both clients initiate a TCP connection at nearly the same time, they deterministically retain one connection and discard the duplicate.

If TCP port `5050` is blocked by a firewall, allow inbound TCP traffic for that port. Do not expose the port to the public Internet.

## Wireshark verification

- Capture Kali traffic on `eth0`, Ubuntu traffic on `vmnet8`, or both.
- Use the display filter `tcp.port == 5050`.
- Select a packet and use **Follow → TCP Stream**.
- The `clear_message` JSON frame must visibly contain the original `text` value.
- After the secure session starts, a `secure_message` frame must show `AES-256-GCM`, a sequence number, Base64 ciphertext, and an authentication tag.
- Search the followed stream for the encrypted message text and confirm it does not appear.
- Save the capture if it will be used as project evidence.

The initial plaintext behavior is intentional for the assignment's pre-encryption stage. Once `SECURE_ACTIVE` is reached, the application accepts only encrypted chat frames and will not fall back to plaintext.

## Local identity and fingerprint

On first launch, each machine generates its own RSA-3072 identity. The key pair and installation metadata are stored outside the repository under:

```text
~/.local/share/cse722-chat/
```

The directory is restricted to the current Linux user (`0700`), and the private key uses mode `0600`. The application never sends the private key to the browser or peer.

Use **Show fingerprint** in the GUI to display the SHA-256 fingerprint of the public identity key. The same machine must display the same fingerprint after the application restarts, while Ubuntu and Kali must display different fingerprints.

If the stored identity is incomplete, corrupt, or contains mismatched keys, startup fails instead of silently generating a replacement identity. Back up or move the entire identity directory together; never copy one client's identity directory to the other machine.

## Public-key exchange and fingerprint verification

Complete the plaintext exchange first. Once each client has sent and received at least one message:

1. On either client, select **Exchange Public Keys**.
2. Both clients display the SHA-256 fingerprint computed from the received RSA public key.
3. On Ubuntu, compare the displayed peer fingerprint with Kali's local fingerprint.
4. On Kali, compare the displayed peer fingerprint with Ubuntu's local fingerprint.
5. If both comparisons match exactly, select **Fingerprints match** on both clients.
6. Confirm both clients reach `IDENTITY_VERIFIED`.

Each confirmation is signed with RSA-PSS/SHA-256 and bound to the current connection and both fingerprints. The event log shows when the peer's signed confirmation is valid. Selecting **Reject fingerprint**, receiving a changed key, or receiving an invalid signature terminates the connection.

Public keys and fingerprints are not secret. Never compare or transmit the private-key files.

## Authenticated AES-key transfer

After both clients reach `IDENTITY_VERIFIED`:

1. Select **Start Secure Session** on either client.
2. The initiator generates a fresh 256-bit AES key in memory, wraps it for the peer with RSA-OAEP/SHA-256, and signs the complete offer with RSA-PSS/SHA-256.
3. Confirm both clients briefly enter `SECURE_NEGOTIATING` and then reach `SECURE_ACTIVE`.
4. Check the event logs for the connection and fingerprint binding, valid RSA-PSS signature, successful RSA-OAEP decryption, and two-way AES-GCM key-possession proofs.

The AES key is never logged, sent in plaintext, or written to disk. Disconnecting erases the in-memory session key, and reconnecting requires a new verification and key-transfer flow. Plaintext chat is disabled once secure negotiation starts.

In Wireshark, the `key_offer` frame visibly identifies `RSA-OAEP-SHA256` and `RSA-PSS-SHA256`, while `key_confirm` and `secure_ready` identify `AES-256-GCM`. Their encrypted fields do not reveal the AES key or confirmation payload.

## Encrypted chat

After both clients reach `SECURE_ACTIVE`, the chat heading and badges change to `ENCRYPTED`. Messages in both directions are protected with AES-256-GCM. The message text, UUID, and timestamp are all inside the ciphertext; only the algorithm, session binding, sender fingerprint, sequence number, ciphertext, and authentication tag remain visible on the wire.

Each direction starts at sequence `1` and uses a deterministic nonce derived from the secure-session ID, sender fingerprint, and sequence. The receiver requires the next exact sequence number. A modified authentication tag or ciphertext, replayed message, out-of-order message, invalid schema, or attempted plaintext downgrade produces a red protocol-failure event, erases the in-memory AES key, and disconnects instead of reverting to plaintext.

## Troubleshooting

- **The peers cannot connect:** Recheck both IPv4 addresses with `ip address`, then ping Ubuntu from Kali and Kali from Ubuntu. Both systems must remain on mutually reachable VMware networks.
- **TCP port 5050 is blocked:** Check the listener with `ss -ltnp | grep ':5050'`. If Ubuntu uses UFW, scope the rule to the VMware subnet with `sudo ufw allow from 172.16.217.0/24 to any port 5050 proto tcp`.
- **Port already in use:** Stop the older application instance before starting another. Only one instance per machine should listen on the configured web and chat ports.
- **The browser cannot open the GUI:** Open `http://localhost:3000` on the same machine running that application. The GUI intentionally binds only to local loopback.
- **Node.js is too old:** Confirm `node --version` reports version 22 or newer before running `npm ci` or the build.
- **Identity startup fails:** Read the reported error. An incomplete, corrupt, or mismatched identity is never silently replaced. Preserve or move the entire identity directory together rather than changing individual key files.
- **The secure-session button is disabled:** Exchange one plaintext message in each direction, exchange public keys, and confirm both fingerprints first.
- **Wireshark shows no packets:** Capture the interface carrying peer traffic—normally Kali `eth0` or Ubuntu `vmnet8`—and apply `tcp.port == 5050` as a display filter rather than a capture filter.
- **The GUI looks stale after an update:** Stop the application, run `npm run build`, restart it, and refresh both browsers.

## Demonstration evidence checklist

- Stable, different local fingerprints on Ubuntu and Kali
- A `PLAINTEXT` GUI badge and capture-visible `clear_message.text`
- Successful fingerprint-signature and AES key-transfer events
- `SECURE_ACTIVE` on both machines
- `ENCRYPTED` badges for messages in both directions
- A capture-visible `secure_message` with `AES-256-GCM`, sequence, ciphertext, and authentication tag
- No match when searching the TCP stream for the unique encrypted message text
- `DISCONNECTED` after shutdown, followed by stable identity and a required fresh secure session after restart

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEB_PORT` | `3000` | Local browser interface port |
| `CHAT_PORT` | `5050` | Peer TCP listener and destination port |
| `CHAT_BIND_ADDRESS` | `0.0.0.0` | Peer TCP listener address |
| `DATA_DIR` | `~/.local/share/cse722-chat` | Persistent identity storage |

Copy `.env.example` as a reference. Environment variables must currently be exported by the shell before starting the app; `.env` files are not loaded automatically.

## Verification

```bash
npm run typecheck
npm test
npm run build
```
