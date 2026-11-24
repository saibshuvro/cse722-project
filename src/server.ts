import { createServer } from "node:http";

import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { attachControlSocket } from "./control.js";

const WEB_BIND_ADDRESS = "127.0.0.1";

const config = loadConfig();
const app = createApp(config);
const server = createServer(app);
const controlSocket = attachControlSocket(server, config);

server.on("error", (error) => {
  console.error("Failed to start the local web server:", error);
  process.exitCode = 1;
});

server.listen(config.webPort, WEB_BIND_ADDRESS, () => {
  console.log(`CSE722 Encrypted Chat: http://localhost:${config.webPort}`);
  console.log(
    `Phase 1 ready; peer TCP will listen on ${config.chatBindAddress}:${config.chatPort} in Phase 2.`,
  );
});

function shutDown(signal: string): void {
  console.log(`Received ${signal}; shutting down.`);
  controlSocket.close();
  server.close((error) => {
    if (error) {
      console.error("Failed to stop cleanly:", error);
      process.exitCode = 1;
    }
  });
}

process.once("SIGINT", () => shutDown("SIGINT"));
process.once("SIGTERM", () => shutDown("SIGTERM"));
