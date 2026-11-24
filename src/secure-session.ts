import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  sign as signBytes,
  timingSafeEqual,
  verify as verifyBytes,
  type KeyObject,
} from "node:crypto";

export const KEY_WRAP_ALGORITHM = "RSA-OAEP-SHA256" as const;
export const SESSION_CIPHER_ALGORITHM = "AES-256-GCM" as const;
export const KEY_OFFER_SIGNATURE_ALGORITHM = "RSA-PSS-SHA256" as const;
export const SESSION_KEY_BYTES = 32;
export const SESSION_ID_BYTES = 16;
export const GCM_AUTH_TAG_BYTES = 16;

type ConfirmationFrameType = "key_confirm" | "secure_ready";

export interface ConfirmationParameters {
  readonly key: Buffer;
  readonly frameType: ConfirmationFrameType;
  readonly connectionId: string;
  readonly sessionId: string;
  readonly senderFingerprint: string;
  readonly recipientFingerprint: string;
  readonly sequence: 0;
}

export interface EncryptedConfirmation {
  readonly ciphertext: string;
  readonly authTag: string;
}

export function generateSessionKey(): Buffer {
  return randomBytes(SESSION_KEY_BYTES);
}

export function generateSecureSessionId(): string {
  return randomBytes(SESSION_ID_BYTES).toString("base64");
}

export function createKeyOfferPayload(
  connectionId: string,
  sessionId: string,
  senderFingerprint: string,
  recipientFingerprint: string,
  wrappedKeyBase64: string,
): Buffer {
  return Buffer.from(
    JSON.stringify([
      1,
      "key_offer",
      connectionId,
      sessionId,
      senderFingerprint,
      recipientFingerprint,
      wrappedKeyBase64,
    ]),
    "utf8",
  );
}

export function wrapSessionKey(publicKey: KeyObject, sessionKey: Buffer): string {
  if (sessionKey.byteLength !== SESSION_KEY_BYTES) {
    throw new Error(`AES-256 session keys must contain ${SESSION_KEY_BYTES} bytes.`);
  }
  return publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    sessionKey,
  ).toString("base64");
}

export function unwrapSessionKey(privateKey: KeyObject, wrappedKeyBase64: string): Buffer {
  const sessionKey = privateDecrypt(
    {
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(wrappedKeyBase64, "base64"),
  );
  if (sessionKey.byteLength !== SESSION_KEY_BYTES) {
    sessionKey.fill(0);
    throw new Error(`Decrypted session key must contain ${SESSION_KEY_BYTES} bytes.`);
  }
  return sessionKey;
}

export function signKeyOffer(
  privateKey: KeyObject,
  connectionId: string,
  sessionId: string,
  senderFingerprint: string,
  recipientFingerprint: string,
  wrappedKeyBase64: string,
): string {
  const payload = createKeyOfferPayload(
    connectionId,
    sessionId,
    senderFingerprint,
    recipientFingerprint,
    wrappedKeyBase64,
  );
  return signBytes("sha256", payload, {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  }).toString("base64");
}

export function verifyKeyOffer(
  publicKey: KeyObject,
  connectionId: string,
  sessionId: string,
  senderFingerprint: string,
  recipientFingerprint: string,
  wrappedKeyBase64: string,
  signatureBase64: string,
): boolean {
  const payload = createKeyOfferPayload(
    connectionId,
    sessionId,
    senderFingerprint,
    recipientFingerprint,
    wrappedKeyBase64,
  );
  return verifyBytes(
    "sha256",
    payload,
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    },
    Buffer.from(signatureBase64, "base64"),
  );
}

export function createGcmNonce(
  sessionId: string,
  senderFingerprint: string,
  sequence: number,
): Buffer {
  if (!Number.isSafeInteger(sequence) || sequence < 0) {
    throw new Error("AES-GCM sequence numbers must be non-negative safe integers.");
  }
  const prefix = createHash("sha256")
    .update(
      JSON.stringify([1, "cse722-chat-gcm-nonce", sessionId, senderFingerprint]),
      "utf8",
    )
    .digest()
    .subarray(0, 4);
  const nonce = Buffer.alloc(12);
  prefix.copy(nonce, 0);
  nonce.writeBigUInt64BE(BigInt(sequence), 4);
  return nonce;
}

function createConfirmationAad(parameters: ConfirmationParameters): Buffer {
  return Buffer.from(
    JSON.stringify([
      1,
      parameters.frameType,
      parameters.connectionId,
      parameters.sessionId,
      parameters.senderFingerprint,
      parameters.sequence,
    ]),
    "utf8",
  );
}

function createConfirmationPlaintext(parameters: ConfirmationParameters): Buffer {
  return Buffer.from(
    JSON.stringify([
      1,
      parameters.frameType,
      parameters.connectionId,
      parameters.sessionId,
      parameters.senderFingerprint,
      parameters.recipientFingerprint,
    ]),
    "utf8",
  );
}

export function encryptKeyConfirmation(
  parameters: ConfirmationParameters,
): EncryptedConfirmation {
  if (parameters.key.byteLength !== SESSION_KEY_BYTES) {
    throw new Error(`AES-256 session keys must contain ${SESSION_KEY_BYTES} bytes.`);
  }
  const nonce = createGcmNonce(
    parameters.sessionId,
    parameters.senderFingerprint,
    parameters.sequence,
  );
  const cipher = createCipheriv("aes-256-gcm", parameters.key, nonce, {
    authTagLength: GCM_AUTH_TAG_BYTES,
  });
  cipher.setAAD(createConfirmationAad(parameters));
  const ciphertext = Buffer.concat([
    cipher.update(createConfirmationPlaintext(parameters)),
    cipher.final(),
  ]);
  return {
    ciphertext: ciphertext.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
  };
}

export function decryptKeyConfirmation(
  parameters: ConfirmationParameters,
  ciphertextBase64: string,
  authTagBase64: string,
): void {
  if (parameters.key.byteLength !== SESSION_KEY_BYTES) {
    throw new Error(`AES-256 session keys must contain ${SESSION_KEY_BYTES} bytes.`);
  }
  const nonce = createGcmNonce(
    parameters.sessionId,
    parameters.senderFingerprint,
    parameters.sequence,
  );
  const decipher = createDecipheriv("aes-256-gcm", parameters.key, nonce, {
    authTagLength: GCM_AUTH_TAG_BYTES,
  });
  decipher.setAAD(createConfirmationAad(parameters));
  decipher.setAuthTag(Buffer.from(authTagBase64, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertextBase64, "base64")),
    decipher.final(),
  ]);
  const expected = createConfirmationPlaintext(parameters);
  if (plaintext.byteLength !== expected.byteLength || !timingSafeEqual(plaintext, expected)) {
    throw new Error("Secure-session confirmation payload is invalid.");
  }
}
