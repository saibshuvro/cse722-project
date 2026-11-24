import { describe, expect, it } from "vitest";

import { createHealthStatus } from "../src/app.js";
import type { AppConfig } from "../src/config.js";

const config: AppConfig = {
  webPort: 3000,
  chatPort: 5050,
  chatBindAddress: "0.0.0.0",
  dataDir: "/tmp/cse722-app-test",
};

describe("health status", () => {
  it("reports runtime health without exposing the data directory", () => {
    const body = createHealthStatus(config);

    expect(body).toEqual({
      status: "ok",
      protocolVersion: 1,
      webPort: 3000,
      chatPort: 5050,
      chatBindAddress: "0.0.0.0",
    });
    expect(JSON.stringify(body)).not.toContain(config.dataDir);
  });
});
