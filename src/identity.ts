import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPair,
  randomUUID,
  type KeyObject,
} from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  readFile,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

export const IDENTITY_ALGORITHM = "RSA-3072" as const;

const PRIVATE_KEY_FILE = "identity-private.pem";
const PUBLIC_KEY_FILE = "identity-public.pem";
const INSTALLATION_FILE = "installation.json";
const STORE_FILE_MODE = 0o600;
const STORE_DIRECTORY_MODE = 0o700;

const installationSchema = z
  .object({
    version: z.literal(1),
    installationId: z.uuid(),
    createdAt: z.iso.datetime({ offset: true }),
  })
  .strict();

interface InstallationRecord {
  readonly version: 1;
  readonly installationId: string;
  readonly createdAt: string;
}

export interface LocalIdentity {
  readonly algorithm: typeof IDENTITY_ALGORITHM;
  readonly installationId: string;
  readonly createdAt: string;
  readonly fingerprint: string;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  readonly publicKeyPem: string;
}

export interface IdentityLoadResult {
  readonly identity: LocalIdentity;
  readonly created: boolean;
}

export interface IdentityPaths {
  readonly dataDir: string;
  readonly privateKey: string;
  readonly publicKey: string;
  readonly installation: string;
}

export class IdentityStoreError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "IdentityStoreError";
  }
}

export function getIdentityPaths(dataDir: string): IdentityPaths {
  return {
    dataDir,
    privateKey: join(dataDir, PRIVATE_KEY_FILE),
    publicKey: join(dataDir, PUBLIC_KEY_FILE),
    installation: join(dataDir, INSTALLATION_FILE),
  };
}

export function fingerprintPublicKey(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" });
  const digest = createHash("sha256").update(der).digest("hex").toUpperCase();
  return digest.match(/.{2}/g)?.join(":") ?? digest;
}

export function importIdentityPublicKey(publicKeyPem: string): {
  readonly publicKey: KeyObject;
  readonly fingerprint: string;
} {
  if (!publicKeyPem.trimStart().startsWith("-----BEGIN PUBLIC KEY-----")) {
    throw new IdentityStoreError("Peer identity must be an SPKI public key.");
  }

  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey(publicKeyPem);
  } catch (error) {
    throw new IdentityStoreError("Peer identity contains an invalid public key.", {
      cause: error,
    });
  }

  if (
    publicKey.asymmetricKeyType !== "rsa" ||
    publicKey.asymmetricKeyDetails?.modulusLength !== 3_072
  ) {
    throw new IdentityStoreError("Peer identity must use an RSA-3072 public key.");
  }

  return {
    publicKey,
    fingerprint: fingerprintPublicKey(publicKey),
  };
}

function generateIdentityKeyPair(): Promise<{
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}> {
  return new Promise((resolve, reject) => {
    generateKeyPair(
      "rsa",
      {
        modulusLength: 3_072,
        publicExponent: 0x10001,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      },
      (error, publicKeyPem, privateKeyPem) => {
        if (error) {
          reject(error);
          return;
        }
        resolve({ publicKeyPem, privateKeyPem });
      },
    );
  });
}

async function pathExists(path: string): Promise<boolean> {
  try {
    const status = await lstat(path);
    if (!status.isFile() || status.isSymbolicLink()) {
      throw new IdentityStoreError(`Identity path is not a regular file: ${path}`);
    }
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

async function commitNewFiles(
  entries: readonly { readonly target: string; readonly content: string }[],
): Promise<void> {
  const temporaryFiles: string[] = [];
  const committedFiles: string[] = [];

  try {
    for (const entry of entries) {
      const temporary = `${entry.target}.${randomUUID()}.tmp`;
      await writeFile(temporary, entry.content, {
        encoding: "utf8",
        flag: "wx",
        mode: STORE_FILE_MODE,
      });
      temporaryFiles.push(temporary);
    }

    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      const temporary = temporaryFiles[index];
      if (!entry || !temporary) {
        throw new IdentityStoreError("Unable to prepare identity store files.");
      }
      await link(temporary, entry.target);
      committedFiles.push(entry.target);
      await unlink(temporary);
    }
  } catch (error) {
    await Promise.all([
      ...temporaryFiles.map((path) => rm(path, { force: true })),
      ...committedFiles.map((path) => rm(path, { force: true })),
    ]);
    throw error;
  }
}

function validateKeyPair(privateKeyPem: string, publicKeyPem: string): {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
} {
  let privateKey: KeyObject;
  let publicKey: KeyObject;
  try {
    privateKey = createPrivateKey(privateKeyPem);
    publicKey = importIdentityPublicKey(publicKeyPem).publicKey;
  } catch (error) {
    throw new IdentityStoreError("Stored identity contains an invalid PEM key.", {
      cause: error,
    });
  }

  if (privateKey.asymmetricKeyType !== "rsa") {
    throw new IdentityStoreError("Stored identity must contain RSA keys.");
  }
  if (
    privateKey.asymmetricKeyDetails?.modulusLength !== 3_072
  ) {
    throw new IdentityStoreError("Stored identity must use RSA-3072 keys.");
  }

  const derivedPublic = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const storedPublic = publicKey.export({ type: "spki", format: "der" });
  if (!derivedPublic.equals(storedPublic)) {
    throw new IdentityStoreError("Stored public key does not match the private key.");
  }

  return { privateKey, publicKey };
}

async function loadExistingIdentity(paths: IdentityPaths): Promise<LocalIdentity> {
  let installationValue: unknown;
  let privateKeyPem: string;
  let publicKeyPem: string;
  try {
    const [installationJson, privatePem, publicPem] = await Promise.all([
      readFile(paths.installation, "utf8"),
      readFile(paths.privateKey, "utf8"),
      readFile(paths.publicKey, "utf8"),
    ]);
    installationValue = JSON.parse(installationJson);
    privateKeyPem = privatePem;
    publicKeyPem = publicPem;
  } catch (error) {
    throw new IdentityStoreError("Unable to read the stored identity.", { cause: error });
  }

  const installation = installationSchema.safeParse(installationValue);
  if (!installation.success) {
    throw new IdentityStoreError("Stored installation metadata is invalid.");
  }

  const { privateKey, publicKey } = validateKeyPair(privateKeyPem, publicKeyPem);
  await Promise.all([
    chmod(paths.dataDir, STORE_DIRECTORY_MODE),
    chmod(paths.privateKey, STORE_FILE_MODE),
    chmod(paths.publicKey, STORE_FILE_MODE),
    chmod(paths.installation, STORE_FILE_MODE),
  ]);

  return {
    algorithm: IDENTITY_ALGORITHM,
    installationId: installation.data.installationId,
    createdAt: installation.data.createdAt,
    fingerprint: fingerprintPublicKey(publicKey),
    privateKey,
    publicKey,
    publicKeyPem,
  };
}

export async function loadOrCreateIdentity(dataDir: string): Promise<IdentityLoadResult> {
  const paths = getIdentityPaths(dataDir);
  await mkdir(paths.dataDir, { recursive: true, mode: STORE_DIRECTORY_MODE });
  await chmod(paths.dataDir, STORE_DIRECTORY_MODE);

  const existence = await Promise.all([
    pathExists(paths.privateKey),
    pathExists(paths.publicKey),
    pathExists(paths.installation),
  ]);
  const existingCount = existence.filter(Boolean).length;

  if (existingCount === existence.length) {
    return { identity: await loadExistingIdentity(paths), created: false };
  }
  if (existingCount !== 0) {
    throw new IdentityStoreError(
      `Identity store in ${dataDir} is incomplete. Restore all identity files or move the directory aside before restarting.`,
    );
  }

  const installation: InstallationRecord = {
    version: 1,
    installationId: randomUUID(),
    createdAt: new Date().toISOString(),
  };

  let generated: Awaited<ReturnType<typeof generateIdentityKeyPair>>;
  try {
    generated = await generateIdentityKeyPair();
    await commitNewFiles([
      { target: paths.privateKey, content: generated.privateKeyPem },
      { target: paths.publicKey, content: generated.publicKeyPem },
      {
        target: paths.installation,
        content: `${JSON.stringify(installation, null, 2)}\n`,
      },
    ]);
  } catch (error) {
    throw new IdentityStoreError("Unable to create the local RSA identity.", {
      cause: error,
    });
  }

  return { identity: await loadExistingIdentity(paths), created: true };
}
