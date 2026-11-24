import { generateKeyPairSync, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  createGcmNonce,
  decryptKeyConfirmation,
  encryptKeyConfirmation,
  generateSecureSessionId,
  generateSessionKey,
  signKeyOffer,
  unwrapSessionKey,
  verifyKeyOffer,
  wrapSessionKey,
} from "../src/secure-session.js";

const FIRST_FINGERPRINT = `${"AA:".repeat(31)}AA`;
const SECOND_FINGERPRINT = `${"BB:".repeat(31)}BB`;

function rsaKeyPair() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2_048,
    publicExponent: 0x10001,
  });
}

describe("secure-session cryptography", () => {
  it("generates fresh AES-256 keys and 128-bit session IDs", () => {
    const firstKey = generateSessionKey();
    const secondKey = generateSessionKey();
    const firstId = generateSecureSessionId();
    const secondId = generateSecureSessionId();

    expect(firstKey).toHaveLength(32);
    expect(secondKey).toHaveLength(32);
    expect(firstKey.equals(secondKey)).toBe(false);
    expect(Buffer.from(firstId, "base64")).toHaveLength(16);
    expect(Buffer.from(secondId, "base64")).toHaveLength(16);
    expect(firstId).not.toBe(secondId);
  });

  it("wraps the AES key and authenticates the complete key offer", () => {
    const sender = rsaKeyPair();
    const recipient = rsaKeyPair();
    const connectionId = randomUUID();
    const sessionId = generateSecureSessionId();
    const key = generateSessionKey();
    const wrappedKey = wrapSessionKey(recipient.publicKey, key);
    const signature = signKeyOffer(
      sender.privateKey,
      connectionId,
      sessionId,
      FIRST_FINGERPRINT,
      SECOND_FINGERPRINT,
      wrappedKey,
    );

    expect(unwrapSessionKey(recipient.privateKey, wrappedKey)).toEqual(key);
    expect(
      verifyKeyOffer(
        sender.publicKey,
        connectionId,
        sessionId,
        FIRST_FINGERPRINT,
        SECOND_FINGERPRINT,
        wrappedKey,
        signature,
      ),
    ).toBe(true);
    expect(
      verifyKeyOffer(
        sender.publicKey,
        connectionId,
        generateSecureSessionId(),
        FIRST_FINGERPRINT,
        SECOND_FINGERPRINT,
        wrappedKey,
        signature,
      ),
    ).toBe(false);
    expect(() => unwrapSessionKey(sender.privateKey, wrappedKey)).toThrow();
  });

  it("protects key-possession confirmations with bound AES-GCM metadata", () => {
    const key = generateSessionKey();
    const parameters = {
      key,
      frameType: "key_confirm" as const,
      connectionId: randomUUID(),
      sessionId: generateSecureSessionId(),
      senderFingerprint: FIRST_FINGERPRINT,
      recipientFingerprint: SECOND_FINGERPRINT,
      sequence: 0 as const,
    };
    const encrypted = encryptKeyConfirmation(parameters);

    expect(() =>
      decryptKeyConfirmation(
        parameters,
        encrypted.ciphertext,
        encrypted.authTag,
      ),
    ).not.toThrow();

    const tamperedTag = Buffer.from(encrypted.authTag, "base64");
    tamperedTag[0] ^= 0x01;
    expect(() =>
      decryptKeyConfirmation(
        parameters,
        encrypted.ciphertext,
        tamperedTag.toString("base64"),
      ),
    ).toThrow();

    expect(
      createGcmNonce(parameters.sessionId, FIRST_FINGERPRINT, 0).equals(
        createGcmNonce(parameters.sessionId, FIRST_FINGERPRINT, 0),
      ),
    ).toBe(true);
    expect(
      createGcmNonce(parameters.sessionId, FIRST_FINGERPRINT, 0).equals(
        createGcmNonce(parameters.sessionId, SECOND_FINGERPRINT, 0),
      ),
    ).toBe(false);
  });
});
