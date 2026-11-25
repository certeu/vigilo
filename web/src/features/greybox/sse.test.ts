import { describe, expect, it } from "vitest";
import { SseParser, type SseItem } from "./sse";

const msgs = (items: SseItem[]) => items.filter((i) => i.type === "message");

describe("SseParser", () => {
  it("parses a frame with id, event and data", () => {
    const p = new SseParser();
    const out = p.push('id: 43\nevent: event\ndata: {"seq":43}\n\n');
    expect(out).toEqual([{ type: "message", event: "event", data: '{"seq":43}', id: "43" }]);
    expect(p.lastEventId).toBe("43");
  });

  it("handles chunks split at arbitrary points, including inside a line and between \\r and \\n", () => {
    const text = 'retry: 3000\r\n\r\nid: 1\r\nevent: event\r\ndata: {"a":1}\r\n\r\nid: 2\ndata: x\n\n';
    for (let cut = 1; cut < text.length; cut++) {
      const p = new SseParser();
      const items = [...p.push(text.slice(0, cut)), ...p.push(text.slice(cut))];
      expect(items.filter((i) => i.type === "retry")).toEqual([{ type: "retry", ms: 3000 }]);
      expect(msgs(items)).toEqual([
        { type: "message", event: "event", data: '{"a":1}', id: "1" },
        { type: "message", event: "message", data: "x", id: "2" },
      ]);
    }
  });

  it("joins multi-line data with \\n", () => {
    const p = new SseParser();
    expect(msgs(p.push("data: a\ndata: b\ndata:\ndata: c\n\n"))[0]).toMatchObject({ data: "a\nb\n\nc" });
  });

  it("reports comments and pings without dispatching a message", () => {
    const p = new SseParser();
    const out = p.push(": ping\n\n: hello\n");
    expect(out).toEqual([{ type: "comment", text: "ping" }, { type: "comment", text: "hello" }]);
  });

  it("does not dispatch frames without data, and resets fields between frames", () => {
    const p = new SseParser();
    const out = p.push("event: orphan\nid: 5\n\ndata: y\n\n");
    expect(out).toEqual([{ type: "message", event: "message", data: "y", id: null }]);
    expect(p.lastEventId).toBe("5");
  });

  it("waits for the blank line before dispatching and tolerates a BOM and unknown fields", () => {
    const p = new SseParser();
    expect(p.push("﻿data: partial\n")).toEqual([]);
    expect(p.push("foo: bar\n\n")).toEqual([{ type: "message", event: "message", data: "partial", id: null }]);
  });

  it("ignores an invalid retry value and keeps colons inside data", () => {
    const p = new SseParser();
    const out = p.push("retry: soon\ndata: a:b: c\n\n");
    expect(out).toEqual([{ type: "message", event: "message", data: "a:b: c", id: null }]);
  });
});
