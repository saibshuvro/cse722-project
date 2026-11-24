# CSE722 Encrypted Chat

A two-peer chat application for demonstrating plaintext communication, manual identity-key verification, authenticated AES-256 key transfer, and AES-256-GCM encrypted messaging.

Phase 2 currently provides direct TCP connection and deliberately unencrypted chat between the Ubuntu host and Kali VM. Identity and cryptographic stages are added in later phases.

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

## Phase 2 demonstration

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

This plaintext behavior is intentional for the assignment's pre-encryption stage. Later phases replace chat frames with AES-256-GCM ciphertext after manual identity verification and authenticated key transfer.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEB_PORT` | `3000` | Local browser interface port |
| `CHAT_PORT` | `5050` | Peer TCP listener and destination port |
| `CHAT_BIND_ADDRESS` | `0.0.0.0` | Peer TCP listener address |
| `DATA_DIR` | `~/.local/share/cse722-chat` | Future identity-key storage |

Copy `.env.example` as a reference. Environment variables must currently be exported by the shell before starting the app; `.env` files are not loaded automatically.

## Verification

```bash
npm run typecheck
npm test
npm run build
```
