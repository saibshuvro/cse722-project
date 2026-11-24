import { mkdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  getIdentityPaths,
  IdentityStoreError,
  loadOrCreateIdentity,
} from "../src/identity.js";

const temporaryDirectories: string[] = [];

async function makeTemporaryDataDir(): Promise<string> {
  const directory = join(
    tmpdir(),
    `cse722-identity-${process.pid}-${Date.now()}-${temporaryDirectories.length}`,
  );
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, {
        recursive: true,
        force: true,
      }),
    ),
  );
});

describe("local identity store", () => {
  it(
    "creates a protected RSA identity and reloads the same fingerprint",
    async () => {
      const dataDir = await makeTemporaryDataDir();
      const first = await loadOrCreateIdentity(dataDir);
      const paths = getIdentityPaths(dataDir);

      expect(first.created).toBe(true);
      expect(first.identity.algorithm).toBe("RSA-3072");
      expect(first.identity.fingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
      expect(first.identity.privateKey.asymmetricKeyDetails?.modulusLength).toBe(3_072);

      const [directoryStatus, privateStatus, publicStatus, installationStatus] =
        await Promise.all([
          stat(dataDir),
          stat(paths.privateKey),
          stat(paths.publicKey),
          stat(paths.installation),
        ]);
      expect(directoryStatus.mode & 0o777).toBe(0o700);
      expect(privateStatus.mode & 0o777).toBe(0o600);
      expect(publicStatus.mode & 0o777).toBe(0o600);
      expect(installationStatus.mode & 0o777).toBe(0o600);

      const second = await loadOrCreateIdentity(dataDir);
      expect(second.created).toBe(false);
      expect(second.identity.installationId).toBe(first.identity.installationId);
      expect(second.identity.fingerprint).toBe(first.identity.fingerprint);
      expect(second.identity.publicKeyPem).toBe(first.identity.publicKeyPem);

      await writeFile(paths.publicKey, "not a public key", "utf8");
      await expect(loadOrCreateIdentity(dataDir)).rejects.toThrow(IdentityStoreError);
    },
    15_000,
  );

  it("rejects an incomplete identity store instead of replacing it", async () => {
    const dataDir = await makeTemporaryDataDir();
    const paths = getIdentityPaths(dataDir);
    await mkdir(dataDir, { recursive: true });
    await writeFile(paths.installation, "{}", "utf8");

    await expect(loadOrCreateIdentity(dataDir)).rejects.toThrow(/incomplete/i);
  });
});
