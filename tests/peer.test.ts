import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import type { AppConfig } from "../src/config.js";
import { loadOrCreateIdentity } from "../src/identity.js";
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

function waitForSnapshot(
  service: PeerService,
  predicate: (snapshot: StateSnapshot) => boolean,
  description: string,
): Promise<StateSnapshot> {
  const current = service.getSnapshot();
  if (predicate(current)) {
    return Promise.resolve(current);
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      unsubscribe();
      reject(new Error(`Timed out waiting for ${description}.`));
    }, 5_000);
    const unsubscribe = service.onState((snapshot) => {
      if (predicate(snapshot)) {
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

  it(
    "verifies identities and establishes an authenticated AES session",
    async () => {
      const firstDirectory = await mkdtemp(join(tmpdir(), "cse722-peer-first-"));
      const secondDirectory = await mkdtemp(join(tmpdir(), "cse722-peer-second-"));
      const [firstIdentity, secondIdentity] = await Promise.all([
        loadOrCreateIdentity(firstDirectory),
        loadOrCreateIdentity(secondDirectory),
      ]);
      const first = new PeerService(testConfig(), firstIdentity.identity);
      const second = new PeerService(testConfig(), secondIdentity.identity);
      const firstSecurityEvents: string[] = [];
      const secondSecurityEvents: string[] = [];
      const removeFirstSecurityListener = first.onSecurityEvent((event) =>
        firstSecurityEvents.push(event.message),
      );
      const removeSecondSecurityListener = second.onSecurityEvent((event) =>
        secondSecurityEvents.push(event.message),
      );

      try {
        await Promise.all([first.start(), second.start()]);
        const firstConnected = waitForState(first, "CONNECTED_CLEAR");
        const secondConnected = waitForState(second, "CONNECTED_CLEAR");
        first.connect("127.0.0.1", second.listeningPort);
        await Promise.all([firstConnected, secondConnected]);

        first.sendClearMessage("identity test hello");
        await waitForIncomingMessage(second);
        const firstClear = waitForState(first, "CLEAR_EXCHANGED");
        const secondClear = waitForState(second, "CLEAR_EXCHANGED");
        second.sendClearMessage("identity test reply");
        await Promise.all([firstClear, secondClear]);

        const firstHasPeerKey = waitForSnapshot(
          first,
          (snapshot) =>
            snapshot.state === "KEYS_UNVERIFIED" && snapshot.peerFingerprint !== null,
          "the first peer identity key",
        );
        const secondHasPeerKey = waitForSnapshot(
          second,
          (snapshot) =>
            snapshot.state === "KEYS_UNVERIFIED" && snapshot.peerFingerprint !== null,
          "the second peer identity key",
        );
        first.exchangeIdentityKeys();

        const [firstUnverified, secondUnverified] = await Promise.all([
          firstHasPeerKey,
          secondHasPeerKey,
        ]);
        expect(firstUnverified.peerFingerprint).toBe(secondIdentity.identity.fingerprint);
        expect(secondUnverified.peerFingerprint).toBe(firstIdentity.identity.fingerprint);

        const firstVerified = waitForState(first, "IDENTITY_VERIFIED");
        const secondVerified = waitForState(second, "IDENTITY_VERIFIED");
        first.verifyPeerFingerprint("accept");
        second.verifyPeerFingerprint("accept");
        const [firstFinal, secondFinal] = await Promise.all([
          firstVerified,
          secondVerified,
        ]);

        expect(firstFinal.localFingerprintVerified).toBe(true);
        expect(firstFinal.peerVerifiedLocalFingerprint).toBe(true);
        expect(secondFinal.localFingerprintVerified).toBe(true);
        expect(secondFinal.peerVerifiedLocalFingerprint).toBe(true);
        expect(firstFinal.permittedActions).toContain("start_secure_session");
        expect(secondFinal.permittedActions).toContain("start_secure_session");

        const firstSecure = waitForState(first, "SECURE_ACTIVE");
        const secondSecure = waitForState(second, "SECURE_ACTIVE");
        first.startSecureSession();
        expect(first.getSnapshot().state).toBe("SECURE_NEGOTIATING");
        const [firstSecureFinal, secondSecureFinal] = await Promise.all([
          firstSecure,
          secondSecure,
        ]);

        expect(firstSecureFinal.permittedActions).not.toContain("send_message");
        expect(secondSecureFinal.permittedActions).not.toContain("send_message");
        expect(() => first.sendClearMessage("plaintext downgrade")).toThrow(/Plaintext/);
        expect(secondSecurityEvents).toEqual(
          expect.arrayContaining([
            expect.stringContaining("Key offer is bound"),
            expect.stringContaining("key-offer signature is valid"),
            expect.stringContaining("session key decrypted"),
            expect.stringContaining("both clients proved possession"),
          ]),
        );
        expect(firstSecurityEvents).toEqual(
          expect.arrayContaining([
            expect.stringContaining("wrapped it for the verified peer"),
            expect.stringContaining("recipient proved possession"),
            expect.stringContaining("Secure session is active"),
          ]),
        );
      } finally {
        removeFirstSecurityListener();
        removeSecondSecurityListener();
        await Promise.all([first.stop(), second.stop()]);
        await Promise.all([
          rm(firstDirectory, { recursive: true, force: true }),
          rm(secondDirectory, { recursive: true, force: true }),
        ]);
      }
    },
    20_000,
  );
});
