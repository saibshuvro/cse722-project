import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { createServer, isIP, type Server as TcpServer, Socket } from "node:net";

import type { AppConfig } from "./config.js";
import {
  encodeFrame,
  FrameDecodeError,
  MAX_MESSAGE_BYTES,
  NdjsonFrameDecoder,
  PROTOCOL_VERSION,
  type ClearMessageFrame,
  type HelloAckFrame,
  type HelloFrame,
  type PeerFrame,
  type ProtocolErrorCode,
} from "./protocol.js";

export type PeerState =
  | "DISCONNECTED"
  | "CONNECTING"
  | "CONNECTED_CLEAR"
  | "CLEAR_EXCHANGED";

export type SecuritySeverity = "info" | "success" | "warning" | "error";

export interface StateSnapshot {
  readonly state: PeerState;
  readonly peerIp: string | null;
  readonly peerPort: number | null;
  readonly direction: "incoming" | "outgoing" | null;
  readonly chatPort: number;
  readonly chatBindAddress: string;
  readonly sentClearMessage: boolean;
  readonly receivedClearMessage: boolean;
  readonly permittedActions: readonly ("connect" | "disconnect" | "send_message")[];
}

export interface ChatMessageEvent {
  readonly type: "chat_message";
  readonly direction: "incoming" | "outgoing";
  readonly security: "PLAINTEXT";
  readonly messageId: string;
  readonly timestamp: string;
  readonly text: string;
}

export interface SecurityEvent {
  readonly type: "security_event";
  readonly severity: SecuritySeverity;
  readonly timestamp: string;
  readonly message: string;
}

type SessionPhase = "WAITING_FOR_HELLO" | "WAITING_FOR_ACK" | "READY";

interface PeerSession {
  readonly socket: Socket;
  readonly decoder: NdjsonFrameDecoder;
  readonly direction: "incoming" | "outgoing";
  readonly peerIp: string;
  readonly peerPort: number;
  connectionId: string;
  phase: SessionPhase;
  peerInstallationId: string | null;
  sentClearMessage: boolean;
  receivedClearMessage: boolean;
  clearExchangeAnnounced: boolean;
  handshakeTimer: NodeJS.Timeout | null;
}

const HANDSHAKE_TIMEOUT_MS = 5_000;

function normalizeIp(address: string | undefined): string {
  if (!address) {
    return "unknown";
  }
  return address.startsWith("::ffff:") ? address.slice(7) : address;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown networking error.";
}

export class PeerService extends EventEmitter {
  private readonly installationId: string;
  private readonly config: AppConfig;
  private readonly inboundSockets = new Set<Socket>();
  private server: TcpServer | null = null;
  private session: PeerSession | null = null;
  private boundChatPort: number;

  constructor(config: AppConfig, installationId: string = randomUUID()) {
    super();
    this.config = config;
    this.installationId = installationId;
    this.boundChatPort = config.chatPort;
  }

  get listeningPort(): number {
    return this.boundChatPort;
  }

  getSnapshot(): StateSnapshot {
    const state = this.getState();
    const permittedActions: StateSnapshot["permittedActions"] =
      state === "DISCONNECTED"
        ? ["connect"]
        : state === "CONNECTING"
          ? ["disconnect"]
          : ["disconnect", "send_message"];

    return {
      state,
      peerIp: this.session?.peerIp ?? null,
      peerPort: this.session?.peerPort ?? null,
      direction: this.session?.direction ?? null,
      chatPort: this.boundChatPort,
      chatBindAddress: this.config.chatBindAddress,
      sentClearMessage: this.session?.sentClearMessage ?? false,
      receivedClearMessage: this.session?.receivedClearMessage ?? false,
      permittedActions,
    };
  }

  async start(): Promise<void> {
    if (this.server) {
      return;
    }

    const server = createServer((socket) => this.acceptIncoming(socket));
    this.server = server;

    await new Promise<void>((resolve, reject) => {
      const handleInitialError = (error: Error): void => {
        server.off("listening", handleListening);
        this.server = null;
        reject(error);
      };
      const handleListening = (): void => {
        server.off("error", handleInitialError);
        resolve();
      };

      server.once("error", handleInitialError);
      server.once("listening", handleListening);
      server.listen(this.config.chatPort, this.config.chatBindAddress);
    });

    const address = server.address();
    if (address && typeof address !== "string") {
      this.boundChatPort = address.port;
    }

    server.on("error", (error) => {
      this.emitSecurity("error", `TCP listener error: ${error.message}`);
    });
    this.emitSecurity(
      "success",
      `Peer TCP listener is ready on ${this.config.chatBindAddress}:${this.boundChatPort}.`,
    );
    this.emitState();
  }

  async stop(): Promise<void> {
    if (this.session) {
      this.endSession(this.session, "Application stopped.", false, true);
    }

    const server = this.server;
    this.server = null;
    if (!server?.listening) {
      return;
    }

    for (const socket of this.inboundSockets) {
      socket.destroy();
    }

    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  connect(peerIp: string, peerPort = this.config.chatPort): void {
    const normalizedIp = peerIp.trim();
    if (isIP(normalizedIp) !== 4) {
      throw new Error("Enter a valid IPv4 address for the peer.");
    }
    if (!Number.isInteger(peerPort) || peerPort < 1 || peerPort > 65_535) {
      throw new Error("Peer port must be between 1 and 65535.");
    }
    if (this.session) {
      throw new Error("Disconnect the current or pending peer before connecting again.");
    }

    const socket = new Socket();
    const session: PeerSession = {
      socket,
      decoder: new NdjsonFrameDecoder(),
      direction: "outgoing",
      peerIp: normalizedIp,
      peerPort,
      connectionId: randomUUID(),
      phase: "WAITING_FOR_ACK",
      peerInstallationId: null,
      sentClearMessage: false,
      receivedClearMessage: false,
      clearExchangeAnnounced: false,
      handshakeTimer: null,
    };
    this.session = session;
    this.attachSession(session);
    this.startHandshakeTimer(session);
    this.emitSecurity("info", `Connecting to ${normalizedIp}:${peerPort}…`);
    this.emitState();

    socket.connect(peerPort, normalizedIp, () => {
      if (this.session !== session) {
        return;
      }
      this.writeFrame(session, {
        v: PROTOCOL_VERSION,
        type: "hello",
        connectionId: session.connectionId,
        installationId: this.installationId,
        dialerId: this.installationId,
      });
    });
  }

  disconnect(): void {
    if (this.session) {
      this.endSession(this.session, "Disconnected by the local user.", true, false);
    }
  }

  sendClearMessage(input: string): void {
    const session = this.requireReadySession();
    const text = input.trim();
    if (text.length === 0) {
      throw new Error("Message cannot be empty.");
    }
    if (Buffer.byteLength(text, "utf8") > MAX_MESSAGE_BYTES) {
      throw new Error(`Message must not exceed ${MAX_MESSAGE_BYTES} UTF-8 bytes.`);
    }

    const frame: ClearMessageFrame = {
      v: PROTOCOL_VERSION,
      type: "clear_message",
      connectionId: session.connectionId,
      messageId: randomUUID(),
      sentAt: new Date().toISOString(),
      text,
    };
    this.writeFrame(session, frame);
    session.sentClearMessage = true;
    this.emitChat({
      type: "chat_message",
      direction: "outgoing",
      security: "PLAINTEXT",
      messageId: frame.messageId,
      timestamp: frame.sentAt,
      text: frame.text,
    });
    this.updateClearExchangeState(session);
    this.emitState();
  }

  onState(listener: (snapshot: StateSnapshot) => void): () => void {
    this.on("state", listener);
    return () => this.off("state", listener);
  }

  onChatMessage(listener: (message: ChatMessageEvent) => void): () => void {
    this.on("chat_message", listener);
    return () => this.off("chat_message", listener);
  }

  onSecurityEvent(listener: (event: SecurityEvent) => void): () => void {
    this.on("security_event", listener);
    return () => this.off("security_event", listener);
  }

  private getState(): PeerState {
    if (!this.session) {
      return "DISCONNECTED";
    }
    if (this.session.phase !== "READY") {
      return "CONNECTING";
    }
    return this.session.sentClearMessage && this.session.receivedClearMessage
      ? "CLEAR_EXCHANGED"
      : "CONNECTED_CLEAR";
  }

  private acceptIncoming(socket: Socket): void {
    socket.setNoDelay(true);
    this.inboundSockets.add(socket);
    socket.once("close", () => this.inboundSockets.delete(socket));
    const peerIp = normalizeIp(socket.remoteAddress);
    const peerPort = socket.remotePort ?? 0;

    if (this.session) {
      const busyFrame: PeerFrame = {
        v: PROTOCOL_VERSION,
        type: "protocol_error",
        connectionId: randomUUID(),
        code: "busy",
        message: "This client already has an active or pending peer connection.",
      };
      socket.end(encodeFrame(busyFrame));
      const destroyTimer = setTimeout(() => socket.destroy(), 500);
      destroyTimer.unref();
      this.emitSecurity("warning", `Rejected an additional connection from ${peerIp}.`);
      return;
    }

    const session: PeerSession = {
      socket,
      decoder: new NdjsonFrameDecoder(),
      direction: "incoming",
      peerIp,
      peerPort,
      connectionId: randomUUID(),
      phase: "WAITING_FOR_HELLO",
      peerInstallationId: null,
      sentClearMessage: false,
      receivedClearMessage: false,
      clearExchangeAnnounced: false,
      handshakeTimer: null,
    };
    this.session = session;
    this.attachSession(session);
    this.startHandshakeTimer(session);
    this.emitSecurity("info", `Incoming TCP connection from ${peerIp}; waiting for handshake.`);
    this.emitState();
  }

  private attachSession(session: PeerSession): void {
    session.socket.setNoDelay(true);
    session.socket.on("data", (chunk) => {
      if (this.session !== session) {
        return;
      }
      try {
        const data = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
        for (const frame of session.decoder.push(data)) {
          this.handleFrame(session, frame);
        }
      } catch (error) {
        const message =
          error instanceof FrameDecodeError ? error.message : "Unable to process peer frame.";
        this.failProtocol(session, "invalid_frame", message);
      }
    });

    session.socket.on("error", (error) => {
      if (this.session !== session) {
        return;
      }
      this.emitSecurity("error", `Peer connection error: ${errorMessage(error)}`);
      this.endSession(session, "Connection failed.", false, true);
    });

    session.socket.on("close", () => {
      if (this.session === session) {
        this.endSession(session, "Peer connection closed.", false, true);
      }
    });
  }

  private handleFrame(session: PeerSession, frame: PeerFrame): void {
    if (frame.type === "protocol_error") {
      this.emitSecurity("error", `Peer rejected the connection (${frame.code}): ${frame.message}`);
      this.endSession(session, "Peer reported a protocol error.", false, true);
      return;
    }

    if (session.phase === "WAITING_FOR_HELLO") {
      if (frame.type !== "hello") {
        this.failProtocol(session, "unexpected_frame", "Expected hello as the first frame.");
        return;
      }
      this.acceptHello(session, frame);
      return;
    }

    if (session.phase === "WAITING_FOR_ACK") {
      if (frame.type !== "hello_ack") {
        this.failProtocol(session, "unexpected_frame", "Expected hello_ack from the peer.");
        return;
      }
      this.acceptHelloAck(session, frame);
      return;
    }

    if (frame.connectionId !== session.connectionId) {
      this.failProtocol(session, "connection_mismatch", "Frame belongs to another connection.");
      return;
    }

    switch (frame.type) {
      case "clear_message":
        this.acceptClearMessage(session, frame);
        break;
      case "goodbye":
        this.emitSecurity("info", `Peer disconnected: ${frame.reason}`);
        this.endSession(session, "Peer disconnected.", false, false);
        break;
      default:
        this.failProtocol(session, "unexpected_frame", `Unexpected ${frame.type} frame.`);
    }
  }

  private acceptHello(session: PeerSession, frame: HelloFrame): void {
    if (frame.dialerId !== frame.installationId) {
      this.failProtocol(session, "invalid_frame", "Handshake dialer identity is invalid.");
      return;
    }
    if (frame.installationId === this.installationId) {
      this.failProtocol(session, "invalid_frame", "A client cannot connect to itself.");
      return;
    }

    session.connectionId = frame.connectionId;
    session.peerInstallationId = frame.installationId;
    this.writeFrame(session, {
      v: PROTOCOL_VERSION,
      type: "hello_ack",
      connectionId: frame.connectionId,
      installationId: this.installationId,
      dialerId: frame.dialerId,
    });
    this.finishHandshake(session);
  }

  private acceptHelloAck(session: PeerSession, frame: HelloAckFrame): void {
    if (frame.connectionId !== session.connectionId) {
      this.failProtocol(session, "connection_mismatch", "Handshake connection ID does not match.");
      return;
    }
    if (frame.dialerId !== this.installationId) {
      this.failProtocol(session, "invalid_frame", "Handshake dialer identity does not match.");
      return;
    }
    if (frame.installationId === this.installationId) {
      this.failProtocol(session, "invalid_frame", "A client cannot connect to itself.");
      return;
    }

    session.peerInstallationId = frame.installationId;
    this.finishHandshake(session);
  }

  private finishHandshake(session: PeerSession): void {
    this.clearHandshakeTimer(session);
    session.phase = "READY";
    this.emitSecurity(
      "success",
      `Direct TCP connection established with ${session.peerIp}:${session.peerPort}.`,
    );
    this.emitState();
  }

  private acceptClearMessage(session: PeerSession, frame: ClearMessageFrame): void {
    session.receivedClearMessage = true;
    this.emitChat({
      type: "chat_message",
      direction: "incoming",
      security: "PLAINTEXT",
      messageId: frame.messageId,
      timestamp: frame.sentAt,
      text: frame.text,
    });
    this.updateClearExchangeState(session);
    this.emitState();
  }

  private updateClearExchangeState(session: PeerSession): void {
    if (
      session.sentClearMessage &&
      session.receivedClearMessage &&
      !session.clearExchangeAnnounced
    ) {
      session.clearExchangeAnnounced = true;
      this.emitSecurity(
        "success",
        "Plaintext messages have been exchanged in both directions. Public-key exchange is the next stage.",
      );
    }
  }

  private requireReadySession(): PeerSession {
    if (!this.session || this.session.phase !== "READY") {
      throw new Error("Connect to a peer before sending a message.");
    }
    return this.session;
  }

  private writeFrame(session: PeerSession, frame: PeerFrame): void {
    if (!session.socket.destroyed && session.socket.writable) {
      session.socket.write(encodeFrame(frame));
    }
  }

  private failProtocol(
    session: PeerSession,
    code: ProtocolErrorCode,
    message: string,
  ): void {
    this.emitSecurity("error", `Protocol failure: ${message}`);
    this.writeFrame(session, {
      v: PROTOCOL_VERSION,
      type: "protocol_error",
      connectionId: session.connectionId,
      code,
      message,
    });
    this.endSession(session, "Disconnected after a protocol failure.", false, false);
  }

  private startHandshakeTimer(session: PeerSession): void {
    session.handshakeTimer = setTimeout(() => {
      if (this.session === session && session.phase !== "READY") {
        this.failProtocol(session, "handshake_timeout", "Peer handshake timed out.");
      }
    }, HANDSHAKE_TIMEOUT_MS);
    session.handshakeTimer.unref();
  }

  private clearHandshakeTimer(session: PeerSession): void {
    if (session.handshakeTimer) {
      clearTimeout(session.handshakeTimer);
      session.handshakeTimer = null;
    }
  }

  private endSession(
    session: PeerSession,
    reason: string,
    notifyPeer: boolean,
    destroySocket: boolean,
  ): void {
    if (this.session !== session) {
      return;
    }

    this.clearHandshakeTimer(session);
    if (notifyPeer && session.phase === "READY") {
      this.writeFrame(session, {
        v: PROTOCOL_VERSION,
        type: "goodbye",
        connectionId: session.connectionId,
        reason,
      });
    }

    this.session = null;
    if (destroySocket) {
      session.socket.destroy();
    } else {
      session.socket.end();
      const destroyTimer = setTimeout(() => session.socket.destroy(), 500);
      destroyTimer.unref();
    }
    this.emitSecurity("info", reason);
    this.emitState();
  }

  private emitState(): void {
    this.emit("state", this.getSnapshot());
  }

  private emitChat(message: ChatMessageEvent): void {
    this.emit("chat_message", message);
  }

  private emitSecurity(severity: SecuritySeverity, message: string): void {
    this.emit("security_event", {
      type: "security_event",
      severity,
      timestamp: new Date().toISOString(),
      message,
    } satisfies SecurityEvent);
  }
}
