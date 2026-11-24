import { homedir } from "node:os";
import { join } from "node:path";

export interface AppConfig {
  readonly webPort: number;
  readonly chatPort: number;
  readonly chatBindAddress: string;
  readonly dataDir: string;
}

const DEFAULT_WEB_PORT = 3000;
const DEFAULT_CHAT_PORT = 5050;
const DEFAULT_CHAT_BIND_ADDRESS = "0.0.0.0";

function parsePort(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.trim() === "") {
    return fallback;
  }

  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be an integer between 1 and 65535.`);
  }

  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`${name} must be an integer between 1 and 65535.`);
  }

  return port;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return {
    webPort: parsePort(env.WEB_PORT, DEFAULT_WEB_PORT, "WEB_PORT"),
    chatPort: parsePort(env.CHAT_PORT, DEFAULT_CHAT_PORT, "CHAT_PORT"),
    chatBindAddress: env.CHAT_BIND_ADDRESS?.trim() || DEFAULT_CHAT_BIND_ADDRESS,
    dataDir:
      env.DATA_DIR?.trim() || join(homedir(), ".local", "share", "cse722-chat"),
  };
}
