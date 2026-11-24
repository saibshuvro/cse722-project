import type { Server as HttpServer } from "node:http";
import { WebSocket, WebSocketServer } from "ws";

import type { AppConfig } from "./config.js";

interface ControlMessage {
  readonly type: "state" | "security_event" | "error";
  readonly [key: string]: unknown;
}

function send(socket: WebSocket, message: ControlMessage): void {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(message));
  }
}

export function attachControlSocket(server: HttpServer, config: AppConfig): WebSocketServer {
  const webSocketServer = new WebSocketServer({ server, path: "/control" });

  webSocketServer.on("connection", (socket) => {
    send(socket, {
      type: "state",
      state: "DISCONNECTED",
      chatPort: config.chatPort,
      chatBindAddress: config.chatBindAddress,
      permittedActions: [],
    });

    send(socket, {
      type: "security_event",
      severity: "info",
      timestamp: new Date().toISOString(),
      message: "Local application backend is ready.",
    });

    socket.on("message", () => {
      send(socket, {
        type: "error",
        message: "Peer commands become available in Phase 2.",
      });
    });
  });

  return webSocketServer;
}
