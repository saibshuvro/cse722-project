import { describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";

describe("loadConfig", () => {
  it("uses the documented defaults", () => {
    const config = loadConfig({});

    expect(config.webPort).toBe(3000);
    expect(config.chatPort).toBe(5050);
    expect(config.chatBindAddress).toBe("0.0.0.0");
    expect(config.dataDir).toContain("cse722-chat");
  });

  it("accepts environment overrides", () => {
    const config = loadConfig({
      WEB_PORT: "3100",
      CHAT_PORT: "5151",
      CHAT_BIND_ADDRESS: "127.0.0.1",
      DATA_DIR: "/tmp/cse722-test-data",
    });

    expect(config).toEqual({
      webPort: 3100,
      chatPort: 5151,
      chatBindAddress: "127.0.0.1",
      dataDir: "/tmp/cse722-test-data",
    });
  });

  it.each(["0", "65536", "3.14", "abc", "-1"])("rejects invalid port %s", (port) => {
    expect(() => loadConfig({ WEB_PORT: port })).toThrow(/WEB_PORT/);
  });
});
