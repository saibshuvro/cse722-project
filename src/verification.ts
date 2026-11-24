import {
  constants,
  sign as signBytes,
  verify as verifyBytes,
  type KeyObject,
} from "node:crypto";

export const VERIFICATION_SIGNATURE_ALGORITHM = "RSA-PSS-SHA256" as const;

export function createFingerprintVerificationPayload(
  connectionId: string,
  senderFingerprint: string,
  recipientFingerprint: string,
): Buffer {
  return Buffer.from(
    JSON.stringify([
      1,
      "fingerprint_verified",
      connectionId,
      senderFingerprint,
      recipientFingerprint,
    ]),
    "utf8",
  );
}

export function signFingerprintVerification(
  privateKey: KeyObject,
  connectionId: string,
  senderFingerprint: string,
  recipientFingerprint: string,
): string {
  const payload = createFingerprintVerificationPayload(
    connectionId,
    senderFingerprint,
    recipientFingerprint,
  );
  return signBytes("sha256", payload, {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  }).toString("base64");
}

export function verifyFingerprintVerification(
  publicKey: KeyObject,
  connectionId: string,
  senderFingerprint: string,
  recipientFingerprint: string,
  signatureBase64: string,
): boolean {
  const payload = createFingerprintVerificationPayload(
    connectionId,
    senderFingerprint,
    recipientFingerprint,
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
