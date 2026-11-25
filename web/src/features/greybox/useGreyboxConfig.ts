import { useEffect, useState } from "react";
import { ApiError } from "../../api/client";
import { greyboxApi } from "./api";
import type { GreyboxConfig } from "./types";

export type GreyboxConfigState =
  | { status: "loading" }
  | { status: "ok"; config: GreyboxConfig }
  /** The endpoint is missing (older server) or failed: treat grey-box as unavailable. */
  | { status: "unavailable"; reason: string };

// One fetch per page load, shared by the sidebar, New analysis and the form.
let cache: Promise<GreyboxConfigState> | null = null;

function load(): Promise<GreyboxConfigState> {
  cache ??= greyboxApi
    .config()
    .then((config): GreyboxConfigState => ({ status: "ok", config }))
    .catch((e: unknown): GreyboxConfigState => {
      cache = null; // allow a retry on the next mount
      if (e instanceof ApiError && e.status === 404)
        return { status: "unavailable", reason: "This server does not provide grey-box analysis." };
      return {
        status: "unavailable",
        reason: `Could not load the grey-box configuration${e instanceof Error ? `: ${e.message}` : "."}`,
      };
    });
  return cache;
}

export function useGreyboxConfig(): GreyboxConfigState {
  const [state, setState] = useState<GreyboxConfigState>({ status: "loading" });
  useEffect(() => {
    let alive = true;
    void load().then((s) => alive && setState(s));
    return () => {
      alive = false;
    };
  }, []);
  return state;
}

/** true only when the server explicitly reports grey-box as enabled. */
export function greyboxEnabled(s: GreyboxConfigState): boolean {
  return s.status === "ok" && s.config.enabled;
}
