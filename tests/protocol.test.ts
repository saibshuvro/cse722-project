import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  decodeFrame,
  encodeFrame,
  FrameDecodeError,
  MAX_FRAME_BYTES,
  NdjsonFrameDecoder,
  PROTOCOL_VERSION,
  type ClearMessageFrame,
} from "../src/protocol.js";

function clearFrame(text = "visible plaintext"): ClearMessageFrame {
  return {
    v: PROTOCOL_VERSION,
    type: "clear_message",
    connectionId: randomUUID(),
    messageId: randomUUID(),
    sentAt: new Date().toISOString(),
    text,
  };
}

describe("peer protocol", () => {
  it("encodes plaintext as newline-delimited JSON", () => {
    const frame = clearFrame("packet capture text");
    const encoded = encodeFrame(frame);

    expect(encoded.at(-1)).toBe(0x0a);
    expect(encoded.toString("utf8")).toContain('"text":"packet capture text"');
    expect(decodeFrame(encoded.subarray(0, -1))).toEqual(frame);
  });

  it("decodes a frame split across TCP chunks", () => {
    const decoder = new NdjsonFrameDecoder();
    const frame = clearFrame();
    const encoded = encodeFrame(frame);

    expect(decoder.push(encoded.subarray(0, 12))).toEqual([]);
    expect(decoder.push(encoded.subarray(12))).toEqual([frame]);
  });

  it("decodes multiple frames from one TCP chunk", () => {
    const decoder = new NdjsonFrameDecoder();
    const first = clearFrame("first");
    const second = clearFrame("second");

    expect(decoder.push(Buffer.concat([encodeFrame(first), encodeFrame(second)]))).toEqual([
      first,
      second,
    ]);
  });

  it("rejects malformed JSON and invalid schemas", () => {
    expect(() => decodeFrame(Buffer.from("not-json"))).toThrow(FrameDecodeError);
    expect(() => decodeFrame(Buffer.from('{"type":"clear_message"}'))).toThrow(
      FrameDecodeError,
    );
  });

  it("rejects oversized incomplete frames", () => {
    const decoder = new NdjsonFrameDecoder();
    expect(() => decoder.push(Buffer.alloc(MAX_FRAME_BYTES + 1, 0x61))).toThrow(
      /exceeds/,
    );
  });

  it("enforces the UTF-8 byte limit instead of character count", () => {
    const oversized = clearFrame("😀".repeat(501));
    const line = Buffer.from(JSON.stringify(oversized), "utf8");
    expect(() => decodeFrame(line)).toThrow(FrameDecodeError);
  });
});
