import { describe, expect, it } from "vitest";

import type { AppConfig } from "../src/config.js";
import {
  PeerService,
  type ChatMessageEvent,
  type PeerState,
  type SecurityEvent,
  type StateSnapshot,
} from "../src/peer.js";

function testConfig(): AppConfig {
  return {
    webPort: 0,
    chatPort: 0,
    chatBindAddress: "127.0.0.1",
    dataDir: "/tmp/cse722-peer-test",
  };
}

function waitForState(service: PeerService, target: PeerState): Promise<StateSnapshot> {
  if (service.getSnapshot().state === target) {
    return Promise.resolve(service.getSnapshot());
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      unsubscribe();
      reject(new Error(`Timed out waiting for ${target}.`));
    }, 3_000);
    const unsubscribe = service.onState((snapshot) => {
      if (snapshot.state === target) {
        clearTimeout(timeout);
        unsubscribe();
        resolve(snapshot);
      }
    });
  });
}

function waitForIncomingMessage(service: PeerService): Promise<ChatMessageEvent> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      unsubscribe();
      reject(new Error("Timed out waiting for an incoming message."));
    }, 3_000);
    const unsubscribe = service.onChatMessage((message) => {
      if (message.direction === "incoming") {
        clearTimeout(timeout);
        unsubscribe();
        resolve(message);
      }
    });
  });
}

function waitForSecurityEvent(
  service: PeerService,
  predicate: (event: SecurityEvent) => boolean,
): Promise<SecurityEvent> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      unsubscribe();
      reject(new Error("Timed out waiting for a security event."));
    }, 3_000);
    const unsubscribe = service.onSecurityEvent((event) => {
      if (predicate(event)) {
        clearTimeout(timeout);
        unsubscribe();
        resolve(event);
      }
    });
  });
}

describe("PeerService", () => {
  it("connects two peers and exchanges plaintext in both directions", async () => {
    const first = new PeerService(testConfig());
    const second = new PeerService(testConfig());

    try {
      await first.start();
      await second.start();

      const firstConnected = waitForState(first, "CONNECTED_CLEAR");
      const secondConnected = waitForState(second, "CONNECTED_CLEAR");
      first.connect("127.0.0.1", second.listeningPort);
      await Promise.all([firstConnected, secondConnected]);

      const secondReceives = waitForIncomingMessage(second);
      first.sendClearMessage("hello from first");
      await expect(secondReceives).resolves.toMatchObject({
        direction: "incoming",
        security: "PLAINTEXT",
        text: "hello from first",
      });

      const firstClearComplete = waitForState(first, "CLEAR_EXCHANGED");
      const secondClearComplete = waitForState(second, "CLEAR_EXCHANGED");
      const firstReceives = waitForIncomingMessage(first);
      second.sendClearMessage("reply from second");

      await expect(firstReceives).resolves.toMatchObject({
        direction: "incoming",
        security: "PLAINTEXT",
        text: "reply from second",
      });
      await Promise.all([firstClearComplete, secondClearComplete]);
    } finally {
      await Promise.all([first.stop(), second.stop()]);
    }
  });

  it("validates peer addresses and requires an active connection for messages", () => {
    const service = new PeerService(testConfig());

    expect(() => service.connect("not-an-ip")).toThrow(/IPv4/);
    expect(() => service.sendClearMessage("hello")).toThrow(/Connect/);
  });

  it("rejects an additional peer without disrupting the active connection", async () => {
    const first = new PeerService(testConfig());
    const second = new PeerService(testConfig());
    const third = new PeerService(testConfig());

    try {
      await Promise.all([first.start(), second.start(), third.start()]);
      const firstConnected = waitForState(first, "CONNECTED_CLEAR");
      const secondConnected = waitForState(second, "CONNECTED_CLEAR");
      first.connect("127.0.0.1", second.listeningPort);
      await Promise.all([firstConnected, secondConnected]);

      const busyEvent = waitForSecurityEvent(third, (event) => event.message.includes("(busy)"));
      third.connect("127.0.0.1", second.listeningPort);
      await busyEvent;

      expect(third.getSnapshot().state).toBe("DISCONNECTED");
      expect(first.getSnapshot().state).toBe("CONNECTED_CLEAR");
      expect(second.getSnapshot().state).toBe("CONNECTED_CLEAR");
    } finally {
      await Promise.all([first.stop(), second.stop(), third.stop()]);
    }
  });
});
