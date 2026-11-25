// No DOM environment: server-render the tab's initial state and the small pure pieces.
import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { ConnectionBadge, LiveActivityTab } from "./LiveActivityTab";
import { RunLiveProvider } from "./RunLiveContext";
import { graphPollMs } from "../graph/ExplorationGraphPanel";
import { LiveIndicator } from "../graph/ExplorationGraph";

describe("Live Activity tab", () => {
  it("renders the connecting state with filters before any event arrives", () => {
    const html = renderToString(
      createElement(MemoryRouter, { initialEntries: ["/?tab=activity&seq=7"] },
        createElement(RunLiveProvider, { runId: "r1", children: createElement(LiveActivityTab) })),
    );
    expect(html).toContain("Connecting");
    expect(html).toContain("Loading events");
    expect(html).toContain("Search events");
  });

  it("labels every connection state in text, not by colour alone", () => {
    for (const [s, label] of [["live", "Live"], ["reconnecting", "Reconnecting"], ["disconnected", "Disconnected"], ["finished", "finished"]] as const) {
      expect(renderToString(createElement(ConnectionBadge, { state: s }))).toContain(label);
    }
  });
});

describe("graph liveness", () => {
  it("polls every 30 s only as a safety net while the stream is live, else every 3 s", () => {
    expect(graphPollMs(true)).toBe(30_000);
    expect(graphPollMs(false)).toBe(3_000);
  });
  it("shows the stream state on the graph", () => {
    const html = (s: Parameters<typeof LiveIndicator>[0]["liveState"]) =>
      renderToString(createElement(LiveIndicator, { liveState: s, time: "10:00:00", reduced: false }));
    expect(html("live")).toContain("Live");
    expect(html("live")).toContain("gx-live-dot");
    expect(html("disconnected")).toContain("Polling");
    expect(html(null)).toContain("Live");
  });
});
