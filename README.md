# CSE722 Encrypted Chat

A two-peer chat application for demonstrating plaintext communication, manual identity-key verification, authenticated AES-256 key transfer, and AES-256-GCM encrypted messaging.

Phase 6 provides the complete chat flow: direct TCP plaintext demonstration, persistent RSA-3072 identities, mutual out-of-band fingerprint verification, authenticated AES-256 session-key transfer, and AES-256-GCM encrypted messaging.

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

## Install and run

Clone or copy the same project to both machines, then run on each:

```bash
npm ci
npm run build
npm start
```

Open <http://localhost:3000> in each machine's browser. Both applications listen for peer TCP connections on port `5050`.

For development, use:

```bash
npm run dev
```

## Network demonstration

Current VMware NAT addresses:

- Ubuntu host (`vmnet8`): `172.16.217.1`
- Kali VM (`eth0`): `172.16.217.130`

1. Start the application on Ubuntu and Kali.
2. On one machine only, enter the other machine's IPv4 address and select **Connect**.
3. Send a plaintext message.
4. Reply from the other machine.
5. Confirm both interfaces show `CLEAR_EXCHANGED` and `PLAINTEXT` badges.

If TCP port `5050` is blocked by a firewall, allow inbound TCP traffic for that port. Do not expose the port to the public Internet.

## Wireshark verification

- Capture Kali traffic on `eth0`, Ubuntu traffic on `vmnet8`, or both.
- Use the display filter `tcp.port == 5050`.
- Select a packet and use **Follow → TCP Stream**.
- The `clear_message` JSON frame must visibly contain the original `text` value.
- After the secure session starts, a `secure_message` frame must show `AES-256-GCM`, a sequence number, Base64 ciphertext, and an authentication tag.
- Search the followed stream for the encrypted message text and confirm it does not appear.

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
