import express, { type Express } from "express";
import { resolve } from "node:path";

import type { AppConfig } from "./config.js";

export interface HealthStatus {
  readonly status: "ok";
  readonly protocolVersion: 1;
  readonly webPort: number;
  readonly chatPort: number;
  readonly chatBindAddress: string;
}

export function createHealthStatus(config: AppConfig): HealthStatus {
  return {
    status: "ok",
    protocolVersion: 1,
    webPort: config.webPort,
    chatPort: config.chatPort,
    chatBindAddress: config.chatBindAddress,
  };
}

export function createApp(config: AppConfig): Express {
  const app = express();
  const publicDir = resolve(process.cwd(), "public");

  app.disable("x-powered-by");
  app.use(express.json({ limit: "16kb" }));

  app.get("/health", (_request, response) => {
    response.json(createHealthStatus(config));
  });

  app.use(express.static(publicDir));

  return app;
}
