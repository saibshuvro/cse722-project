import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import WebSocket from "ws";

interface ControlMessage {
  readonly type: string;
  readonly [key: string]: unknown;
}

interface RunningApp {
  readonly child: ChildProcess;
  readonly webPort: number;
}

class ControlClient {
  private readonly messages: ControlMessage[] = [];
  private readonly waiters = new Set<{
    readonly since: number;
    readonly predicate: (message: ControlMessage) => boolean;
    readonly resolve: (message: ControlMessage) => void;
    readonly reject: (error: Error) => void;
    readonly timeout: NodeJS.Timeout;
  }>();

  private constructor(private readonly socket: WebSocket) {
    socket.on("message", (data) => {
      const message = JSON.parse(data.toString()) as ControlMessage;
      const index = this.messages.push(message) - 1;
      for (const waiter of this.waiters) {
        if (index >= waiter.since && waiter.predicate(message)) {
          clearTimeout(waiter.timeout);
          this.waiters.delete(waiter);
          waiter.resolve(message);
        }
      }
    });
  }

  static connect(webPort: number): Promise<ControlClient> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(`ws://127.0.0.1:${webPort}/control`);
      const handleError = (error: Error): void => {
        socket.off("open", handleOpen);
        reject(error);
      };
      const handleOpen = (): void => {
        socket.off("error", handleError);
        resolve(new ControlClient(socket));
      };
      socket.once("error", handleError);
      socket.once("open", handleOpen);
    });
  }

  mark(): number {
    return this.messages.length;
  }

  send(command: object): void {
    this.socket.send(JSON.stringify(command));
  }

  waitFor(
    predicate: (message: ControlMessage) => boolean,
    since = 0,
    description = "control message",
  ): Promise<ControlMessage> {
    const existing = this.messages
      .slice(since)
      .find((message) => predicate(message));
    if (existing) {
      return Promise.resolve(existing);
    }

    return new Promise((resolve, reject) => {
      const waiter = {
        since,
        predicate,
        resolve,
        reject,
        timeout: setTimeout(() => {
          this.waiters.delete(waiter);
          reject(new Error(`Timed out waiting for ${description}.`));
        }, 10_000),
      };
      this.waiters.add(waiter);
    });
  }

  close(): void {
    for (const waiter of this.waiters) {
      clearTimeout(waiter.timeout);
      waiter.reject(new Error("Control client closed."));
    }
    this.waiters.clear();
    this.socket.close();
  }
}

function stateIs(state: string): (message: ControlMessage) => boolean {
  return (message) => message.type === "state" && message.state === state;
}

function getFreePort(host = "127.0.0.1"): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, host, () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Unable to allocate a test port."));
        return;
      }
      const { port } = address;
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

function startApp(options: {
  readonly webPort: number;
  readonly chatPort: number;
  readonly chatBindAddress: string;
  readonly dataDir: string;
}): Promise<RunningApp> {
  const child = spawn(
    process.execPath,
    ["--import", "tsx", join(process.cwd(), "src", "server.ts")],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        WEB_PORT: String(options.webPort),
        CHAT_PORT: String(options.chatPort),
        CHAT_BIND_ADDRESS: options.chatBindAddress,
        DATA_DIR: options.dataDir,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  return new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`Timed out starting application.\n${output}`));
    }, 20_000);
    const collect = (chunk: Buffer): void => {
      output += chunk.toString("utf8");
      if (output.includes("Peer TCP listener:")) {
        clearTimeout(timeout);
        child.off("exit", handleExit);
        resolve({ child, webPort: options.webPort });
      }
    };
    const handleExit = (code: number | null): void => {
      clearTimeout(timeout);
      reject(new Error(`Application exited during startup (${String(code)}).\n${output}`));
    };
    child.stdout?.on("data", collect);
    child.stderr?.on("data", collect);
    child.once("exit", handleExit);
  });
}

async function stopApp(app: RunningApp | null): Promise<void> {
  if (!app || app.child.exitCode !== null || app.child.signalCode !== null) {
    return;
  }
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      app.child.kill("SIGKILL");
      resolve();
    }, 5_000);
    timeout.unref();
    app.child.once("exit", () => {
      clearTimeout(timeout);
      resolve();
    });
    app.child.kill("SIGTERM");
  });
}

describe("two-process application integration", () => {
  it(
    "completes the secure workflow and preserves only identity across restart",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "cse722-process-integration-"));
      const firstDataDir = join(root, "first");
      const secondDataDir = join(root, "second");
      const [firstWebPort, secondWebPort, chatPort] = await Promise.all([
        getFreePort(),
        getFreePort(),
        getFreePort(),
      ]);
      let firstApp: RunningApp | null = null;
      let secondApp: RunningApp | null = null;
      let firstControl: ControlClient | null = null;
      let secondControl: ControlClient | null = null;

      try {
        [firstApp, secondApp] = await Promise.all([
          startApp({
            webPort: firstWebPort,
            chatPort,
            chatBindAddress: "127.0.0.1",
            dataDir: firstDataDir,
          }),
          startApp({
            webPort: secondWebPort,
            chatPort,
            chatBindAddress: "127.0.0.2",
            dataDir: secondDataDir,
          }),
        ]);
        [firstControl, secondControl] = await Promise.all([
          ControlClient.connect(firstWebPort),
          ControlClient.connect(secondWebPort),
        ]);

        const [firstIdentity, secondIdentity] = await Promise.all([
          firstControl.waitFor((message) => message.type === "identity", 0, "first identity"),
          secondControl.waitFor((message) => message.type === "identity", 0, "second identity"),
        ]);
        expect(firstIdentity.fingerprint).not.toBe(secondIdentity.fingerprint);

        let firstMark = firstControl.mark();
        let secondMark = secondControl.mark();
        firstControl.send({ type: "connect", peerIp: "127.0.0.2" });
        await Promise.all([
          firstControl.waitFor(stateIs("CONNECTED_CLEAR"), firstMark, "first connection"),
          secondControl.waitFor(stateIs("CONNECTED_CLEAR"), secondMark, "second connection"),
        ]);

        secondMark = secondControl.mark();
        firstControl.send({ type: "send_message", text: "process plaintext hello" });
        await secondControl.waitFor(
          (message) =>
            message.type === "chat_message" &&
            message.direction === "incoming" &&
            message.security === "PLAINTEXT" &&
            message.text === "process plaintext hello",
          secondMark,
          "incoming plaintext message",
        );

        firstMark = firstControl.mark();
        secondMark = secondControl.mark();
        secondControl.send({ type: "send_message", text: "process plaintext reply" });
        await Promise.all([
          firstControl.waitFor(stateIs("CLEAR_EXCHANGED"), firstMark, "first clear exchange"),
          secondControl.waitFor(stateIs("CLEAR_EXCHANGED"), secondMark, "second clear exchange"),
        ]);

        firstMark = firstControl.mark();
        secondMark = secondControl.mark();
        firstControl.send({ type: "exchange_keys" });
        await Promise.all([
          firstControl.waitFor(
            (message) =>
              message.type === "state" &&
              message.state === "KEYS_UNVERIFIED" &&
              typeof message.peerFingerprint === "string",
            firstMark,
            "first peer fingerprint",
          ),
          secondControl.waitFor(
            (message) =>
              message.type === "state" &&
              message.state === "KEYS_UNVERIFIED" &&
              typeof message.peerFingerprint === "string",
            secondMark,
            "second peer fingerprint",
          ),
        ]);

        firstMark = firstControl.mark();
        secondMark = secondControl.mark();
        firstControl.send({
          type: "verify_fingerprint",
          decision: "accept",
        });
        secondControl.send({
          type: "verify_fingerprint",
          decision: "accept",
        });
        await Promise.all([
          firstControl.waitFor(stateIs("IDENTITY_VERIFIED"), firstMark, "first verification"),
          secondControl.waitFor(stateIs("IDENTITY_VERIFIED"), secondMark, "second verification"),
        ]);

        firstMark = firstControl.mark();
        secondMark = secondControl.mark();
        firstControl.send({ type: "start_secure_session" });
        await Promise.all([
          firstControl.waitFor(stateIs("SECURE_ACTIVE"), firstMark, "first secure session"),
          secondControl.waitFor(stateIs("SECURE_ACTIVE"), secondMark, "second secure session"),
        ]);

        secondMark = secondControl.mark();
        firstControl.send({ type: "send_message", text: "process encrypted hello" });
        await secondControl.waitFor(
          (message) =>
            message.type === "chat_message" &&
            message.direction === "incoming" &&
            message.security === "ENCRYPTED" &&
            message.text === "process encrypted hello",
          secondMark,
          "incoming encrypted message",
        );

        firstMark = firstControl.mark();
        secondControl.send({ type: "send_message", text: "process encrypted reply" });
        await firstControl.waitFor(
          (message) =>
            message.type === "chat_message" &&
            message.direction === "incoming" &&
            message.security === "ENCRYPTED" &&
            message.text === "process encrypted reply",
          firstMark,
          "encrypted reply",
        );

        firstMark = firstControl.mark();
        secondMark = secondControl.mark();
        firstControl.send({ type: "disconnect" });
        await Promise.all([
          firstControl.waitFor(stateIs("DISCONNECTED"), firstMark, "first disconnect"),
          secondControl.waitFor(stateIs("DISCONNECTED"), secondMark, "second disconnect"),
        ]);

        firstControl.close();
        firstControl = null;
        await stopApp(firstApp);
        firstApp = await startApp({
          webPort: firstWebPort,
          chatPort,
          chatBindAddress: "127.0.0.1",
          dataDir: firstDataDir,
        });
        firstControl = await ControlClient.connect(firstWebPort);
        const restartedIdentity = await firstControl.waitFor(
          (message) => message.type === "identity",
          0,
          "restarted identity",
        );
        const restartedState = await firstControl.waitFor(
          stateIs("DISCONNECTED"),
          0,
          "restarted disconnected state",
        );

        expect(restartedIdentity.fingerprint).toBe(firstIdentity.fingerprint);
        expect(restartedState.permittedActions).toEqual(["connect"]);
      } finally {
        firstControl?.close();
        secondControl?.close();
        await Promise.all([stopApp(firstApp), stopApp(secondApp)]);
        await rm(root, { recursive: true, force: true });
      }
    },
    60_000,
  );
});
