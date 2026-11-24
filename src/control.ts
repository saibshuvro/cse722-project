import type { Server as HttpServer } from "node:http";
import { z } from "zod";
import { WebSocket, WebSocketServer, type RawData } from "ws";

import type { AppConfig } from "./config.js";
import {
  PeerService,
  type ChatMessageEvent,
  type SecurityEvent,
  type StateSnapshot,
} from "./peer.js";
import { MAX_MESSAGE_BYTES } from "./protocol.js";

interface ControlIdentity {
  readonly algorithm: "RSA-3072";
  readonly fingerprint: string;
  readonly createdAt: string;
}

const controlCommandSchema = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("connect"),
      peerIp: z.string().trim().min(1).max(45),
    })
    .strict(),
  z.object({ type: z.literal("disconnect") }).strict(),
  z.object({ type: z.literal("exchange_keys") }).strict(),
  z.object({ type: z.literal("start_secure_session") }).strict(),
  z
    .object({
      type: z.literal("verify_fingerprint"),
      decision: z.enum(["accept", "reject"]),
    })
    .strict(),
  z
    .object({
      type: z.literal("send_message"),
      text: z
        .string()
        .trim()
        .min(1)
        .refine((value) => Buffer.byteLength(value, "utf8") <= MAX_MESSAGE_BYTES),
    })
    .strict(),
]);

type BackendMessage =
  | ({ readonly type: "state" } & StateSnapshot)
  | ChatMessageEvent
  | SecurityEvent
  | {
      readonly type: "identity";
      readonly algorithm: "RSA-3072";
      readonly fingerprint: string;
      readonly createdAt: string;
    }
  | { readonly type: "error"; readonly message: string };

function send(socket: WebSocket, message: BackendMessage): void {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(message));
  }
}

function safeErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unable to process the command.";
}

function toBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) {
    return data;
  }
  if (Array.isArray(data)) {
    return Buffer.concat(data);
  }
  return Buffer.from(data);
}

export function attachControlSocket(
  server: HttpServer,
  config: AppConfig,
  peerService: PeerService,
  identity: ControlIdentity,
  identityCreated: boolean,
): WebSocketServer {
  const webSocketServer = new WebSocketServer({ server, path: "/control" });

  const broadcast = (message: BackendMessage): void => {
    for (const client of webSocketServer.clients) {
      send(client, message);
    }
  };

  const removeStateListener = peerService.onState((snapshot) => {
    broadcast({ type: "state", ...snapshot });
  });
  const removeChatListener = peerService.onChatMessage((message) => broadcast(message));
  const removeSecurityListener = peerService.onSecurityEvent((event) => broadcast(event));

  webSocketServer.on("connection", (socket) => {
    send(socket, { type: "state", ...peerService.getSnapshot() });
    send(socket, {
      type: "identity",
      algorithm: identity.algorithm,
      fingerprint: identity.fingerprint,
      createdAt: identity.createdAt,
    });
    send(socket, {
      type: "security_event",
      severity: "info",
      timestamp: new Date().toISOString(),
      message: identityCreated
        ? `Generated a new ${identity.algorithm} identity and stored it locally.`
        : `Loaded the existing ${identity.algorithm} identity from local storage.`,
    });
    send(socket, {
      type: "security_event",
      severity: "info",
      timestamp: new Date().toISOString(),
      message: `Local backend is ready; TCP listener uses ${config.chatBindAddress}:${peerService.listeningPort}.`,
    });

    socket.on("message", (data, isBinary) => {
      const payload = toBuffer(data);
      if (isBinary || payload.byteLength > 16 * 1024) {
        send(socket, { type: "error", message: "Invalid local control message." });
        return;
      }

      let value: unknown;
      try {
        value = JSON.parse(payload.toString("utf8"));
      } catch {
        send(socket, { type: "error", message: "Control message must be valid JSON." });
        return;
      }

      const result = controlCommandSchema.safeParse(value);
      if (!result.success) {
        send(socket, { type: "error", message: "Invalid or unavailable control command." });
        return;
      }

      try {
        switch (result.data.type) {
          case "connect":
            peerService.connect(result.data.peerIp);
            break;
          case "disconnect":
            peerService.disconnect();
            break;
          case "exchange_keys":
            peerService.exchangeIdentityKeys();
            break;
          case "verify_fingerprint":
            peerService.verifyPeerFingerprint(result.data.decision);
            break;
          case "start_secure_session":
            peerService.startSecureSession();
            break;
          case "send_message":
            peerService.sendClearMessage(result.data.text);
            break;
        }
      } catch (error) {
        send(socket, { type: "error", message: safeErrorMessage(error) });
      }
    });
  });

  webSocketServer.on("close", () => {
    removeStateListener();
    removeChatListener();
    removeSecurityListener();
  });

  return webSocketServer;
}
