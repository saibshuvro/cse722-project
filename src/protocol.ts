import { z } from "zod";

export const PROTOCOL_VERSION = 1 as const;
export const MAX_FRAME_BYTES = 64 * 1024;
export const MAX_MESSAGE_BYTES = 2_000;

const uuidSchema = z.uuid();
const timestampSchema = z.iso.datetime({ offset: true });
const messageTextSchema = z
  .string()
  .min(1)
  .refine((value) => Buffer.byteLength(value, "utf8") <= MAX_MESSAGE_BYTES, {
    message: `Message must not exceed ${MAX_MESSAGE_BYTES} UTF-8 bytes.`,
  });
const fingerprintSchema = z.string().regex(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
const signatureSchema = z
  .string()
  .min(1)
  .max(1_024)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/);
const base64Schema = z
  .string()
  .min(1)
  .max(2_048)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/);
const sessionIdSchema = z.string().regex(/^[A-Za-z0-9+/]{22}==$/);
const authTagSchema = z.string().regex(/^[A-Za-z0-9+/]{22}==$/);

const helloSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("hello"),
    connectionId: uuidSchema,
    installationId: uuidSchema,
    dialerId: uuidSchema,
  })
  .strict();

const helloAckSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("hello_ack"),
    connectionId: uuidSchema,
    installationId: uuidSchema,
    dialerId: uuidSchema,
  })
  .strict();

const clearMessageSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("clear_message"),
    connectionId: uuidSchema,
    messageId: uuidSchema,
    sentAt: timestampSchema,
    text: messageTextSchema,
  })
  .strict();

const identityRequestSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("identity_request"),
    connectionId: uuidSchema,
    requestId: uuidSchema,
  })
  .strict();

const identityKeySchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("identity_key"),
    connectionId: uuidSchema,
    requestId: uuidSchema,
    algorithm: z.literal("RSA-3072"),
    publicKeyPem: z.string().min(1).max(8_192),
  })
  .strict();

const fingerprintVerifiedSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("fingerprint_verified"),
    connectionId: uuidSchema,
    senderFingerprint: fingerprintSchema,
    recipientFingerprint: fingerprintSchema,
    signatureAlgorithm: z.literal("RSA-PSS-SHA256"),
    signature: signatureSchema,
  })
  .strict();

const keyOfferSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("key_offer"),
    connectionId: uuidSchema,
    sessionId: sessionIdSchema,
    senderFingerprint: fingerprintSchema,
    recipientFingerprint: fingerprintSchema,
    algorithm: z.literal("RSA-OAEP-SHA256"),
    wrappedKey: base64Schema,
    signatureAlgorithm: z.literal("RSA-PSS-SHA256"),
    signature: signatureSchema,
  })
  .strict();

const keyConfirmSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("key_confirm"),
    connectionId: uuidSchema,
    sessionId: sessionIdSchema,
    senderFingerprint: fingerprintSchema,
    algorithm: z.literal("AES-256-GCM"),
    sequence: z.literal(0),
    ciphertext: base64Schema,
    authTag: authTagSchema,
  })
  .strict();

const secureReadySchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("secure_ready"),
    connectionId: uuidSchema,
    sessionId: sessionIdSchema,
    senderFingerprint: fingerprintSchema,
    algorithm: z.literal("AES-256-GCM"),
    sequence: z.literal(0),
    ciphertext: base64Schema,
    authTag: authTagSchema,
  })
  .strict();

const protocolErrorSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("protocol_error"),
    connectionId: uuidSchema,
    code: z.enum([
      "busy",
      "handshake_timeout",
      "invalid_frame",
      "unexpected_frame",
      "connection_mismatch",
    ]),
    message: z.string().min(1).max(240),
  })
  .strict();

const goodbyeSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    type: z.literal("goodbye"),
    connectionId: uuidSchema,
    reason: z.string().min(1).max(240),
  })
  .strict();

export const peerFrameSchema = z.discriminatedUnion("type", [
  helloSchema,
  helloAckSchema,
  clearMessageSchema,
  identityRequestSchema,
  identityKeySchema,
  fingerprintVerifiedSchema,
  keyOfferSchema,
  keyConfirmSchema,
  secureReadySchema,
  protocolErrorSchema,
  goodbyeSchema,
]);

export type PeerFrame = z.infer<typeof peerFrameSchema>;
export type HelloFrame = z.infer<typeof helloSchema>;
export type HelloAckFrame = z.infer<typeof helloAckSchema>;
export type ClearMessageFrame = z.infer<typeof clearMessageSchema>;
export type IdentityRequestFrame = z.infer<typeof identityRequestSchema>;
export type IdentityKeyFrame = z.infer<typeof identityKeySchema>;
export type FingerprintVerifiedFrame = z.infer<typeof fingerprintVerifiedSchema>;
export type KeyOfferFrame = z.infer<typeof keyOfferSchema>;
export type KeyConfirmFrame = z.infer<typeof keyConfirmSchema>;
export type SecureReadyFrame = z.infer<typeof secureReadySchema>;
export type ProtocolErrorFrame = z.infer<typeof protocolErrorSchema>;
export type ProtocolErrorCode = ProtocolErrorFrame["code"];

export class FrameDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FrameDecodeError";
  }
}

export function encodeFrame(frame: PeerFrame): Buffer {
  const encoded = Buffer.from(`${JSON.stringify(frame)}\n`, "utf8");
  if (encoded.byteLength > MAX_FRAME_BYTES + 1) {
    throw new FrameDecodeError(`Encoded frame exceeds ${MAX_FRAME_BYTES} bytes.`);
  }
  return encoded;
}

export function decodeFrame(line: Buffer): PeerFrame {
  if (line.byteLength === 0) {
    throw new FrameDecodeError("Received an empty protocol frame.");
  }
  if (line.byteLength > MAX_FRAME_BYTES) {
    throw new FrameDecodeError(`Protocol frame exceeds ${MAX_FRAME_BYTES} bytes.`);
  }

  let value: unknown;
  try {
    value = JSON.parse(line.toString("utf8"));
  } catch {
    throw new FrameDecodeError("Received malformed JSON from the peer.");
  }

  const result = peerFrameSchema.safeParse(value);
  if (!result.success) {
    throw new FrameDecodeError("Received a frame that does not match protocol version 1.");
  }
  return result.data;
}

export class NdjsonFrameDecoder {
  private buffered = Buffer.alloc(0);

  push(chunk: Buffer): PeerFrame[] {
    this.buffered = Buffer.concat([this.buffered, chunk]);
    const frames: PeerFrame[] = [];

    let newlineIndex = this.buffered.indexOf(0x0a);
    while (newlineIndex !== -1) {
      let line = this.buffered.subarray(0, newlineIndex);
      this.buffered = this.buffered.subarray(newlineIndex + 1);

      if (line.at(-1) === 0x0d) {
        line = line.subarray(0, -1);
      }
      frames.push(decodeFrame(line));
      newlineIndex = this.buffered.indexOf(0x0a);
    }

    if (this.buffered.byteLength > MAX_FRAME_BYTES) {
      throw new FrameDecodeError(`Protocol frame exceeds ${MAX_FRAME_BYTES} bytes.`);
    }

    return frames;
  }
}
