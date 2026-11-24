import { createServer, type Server as HttpServer } from "node:http";

import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { attachControlSocket } from "./control.js";
import { loadOrCreateIdentity } from "./identity.js";
import { PeerService } from "./peer.js";

const WEB_BIND_ADDRESS = "127.0.0.1";

function listenHttp(server: HttpServer, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const handleError = (error: Error): void => {
      server.off("listening", handleListening);
      reject(error);
    };
    const handleListening = (): void => {
      server.off("error", handleError);
      resolve();
    };
    server.once("error", handleError);
    server.once("listening", handleListening);
    server.listen(port, WEB_BIND_ADDRESS);
  });
}

async function main(): Promise<void> {
  const config = loadConfig();
  const identityResult = await loadOrCreateIdentity(config.dataDir);
  const peerService = new PeerService(config, identityResult.identity);
  await peerService.start();

  const app = createApp(config);
  const server = createServer(app);
  const controlSocket = attachControlSocket(
    server,
    config,
    peerService,
    {
      algorithm: identityResult.identity.algorithm,
      fingerprint: identityResult.identity.fingerprint,
      createdAt: identityResult.identity.createdAt,
    },
    identityResult.created,
  );
  try {
    await listenHttp(server, config.webPort);
  } catch (error) {
    controlSocket.close();
    await peerService.stop();
    throw error;
  }

  console.log(`CSE722 Encrypted Chat: http://localhost:${config.webPort}`);
  console.log(`Peer TCP listener: ${config.chatBindAddress}:${peerService.listeningPort}`);
  console.log(`Local ${identityResult.identity.algorithm} fingerprint: ${identityResult.identity.fingerprint}`);

  let shuttingDown = false;
  const shutDown = async (signal: string): Promise<void> => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    console.log(`Received ${signal}; shutting down.`);

    for (const client of controlSocket.clients) {
      client.terminate();
    }
    controlSocket.close();
    await peerService.stop();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };

  process.once("SIGINT", () => void shutDown("SIGINT"));
  process.once("SIGTERM", () => void shutDown("SIGTERM"));
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown startup error.";
  console.error(`Failed to start the application: ${message}`);
  process.exitCode = 1;
});
