# CSE722 Encrypted Chat

A two-peer chat application for demonstrating plaintext communication, manual identity-key verification, authenticated AES-256 key transfer, and AES-256-GCM encrypted messaging.

The project is being implemented in phases. Phase 1 provides the TypeScript/Node.js foundation, local browser interface, control WebSocket, configuration, health endpoint, and automated checks.

## Requirements

- Node.js 22 or newer
- npm

## Development

```bash
npm install
npm run dev
```

Open <http://localhost:3000>.

## Verification

```bash
npm run typecheck
npm test
npm run build
npm start
```

The complete Ubuntu/Kali setup and demonstration instructions will be added as the networking and cryptographic phases are implemented.
