// Incremental Server-Sent Events parser (WHATWG "Event stream interpretation").
// Feed it decoded text chunks of any size; it returns the complete items found so far.
// Line endings may be \n, \r or \r\n, and a chunk may end anywhere (even between \r and \n).

export type SseItem =
  | { type: "message"; event: string; data: string; id: string | null }
  | { type: "comment"; text: string }
  | { type: "retry"; ms: number };

export class SseParser {
  private buf = "";
  private started = false;
  private event = "";
  private data: string[] = [];
  private hasData = false;
  private id: string | null = null;
  /** Last `id:` seen (persists across messages, like EventSource.lastEventId). */
  lastEventId = "";

  push(chunk: string): SseItem[] {
    if (!chunk) return [];
    this.buf += chunk;
    if (!this.started) {
      if (this.buf.charCodeAt(0) === 0xfeff) this.buf = this.buf.slice(1);
      this.started = true;
    }
    const out: SseItem[] = [];
    let start = 0;
    const s = this.buf;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c !== 10 && c !== 13) continue;
      if (c === 13) {
        if (i === s.length - 1) break; // maybe the first half of \r\n: wait for more
        const line = s.slice(start, i);
        if (s.charCodeAt(i + 1) === 10) i++;
        start = i + 1;
        this.line(line, out);
      } else {
        this.line(s.slice(start, i), out);
        start = i + 1;
      }
    }
    this.buf = s.slice(start);
    return out;
  }

  private line(line: string, out: SseItem[]): void {
    if (line === "") {
      if (this.hasData) {
        out.push({ type: "message", event: this.event || "message", data: this.data.join("\n"), id: this.id });
      }
      this.event = "";
      this.data = [];
      this.hasData = false;
      this.id = null;
      return;
    }
    if (line.charCodeAt(0) === 58) {
      out.push({ type: "comment", text: line.slice(1).replace(/^ /, "") });
      return;
    }
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.charCodeAt(0) === 32) value = value.slice(1);
    switch (field) {
      case "event":
        this.event = value;
        break;
      case "data":
        this.data.push(value);
        this.hasData = true;
        break;
      case "id":
        if (!value.includes("\u0000")) {
          this.id = value;
          this.lastEventId = value;
        }
        break;
      case "retry":
        if (/^\d+$/.test(value)) out.push({ type: "retry", ms: Number(value) });
        break;
      default:
        break;
    }
  }
}
