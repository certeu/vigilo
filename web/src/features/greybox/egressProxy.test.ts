import { describe, expect, it } from "vitest";
import {
  buildProxyPayload, classifyEgressFailure, DIRECT_HINT, egressFailure, hostMatches, parseHosts,
  proxyChoices, validateAllowedHost, validateProxyForm, validateProxyUrl, type ProxyFormValues,
} from "./egressProxy";

describe("validateProxyUrl", () => {
  it("accepts http(s) with a port", () => {
    expect(validateProxyUrl("http://proxy.example.org:3128")).toBeNull();
    expect(validateProxyUrl("https://proxy.example.org:8443/")).toBeNull();
    expect(validateProxyUrl("http://10.0.0.1:80")).toBeNull();
  });
  it("rejects bad schemes, missing port, path, userinfo", () => {
    expect(validateProxyUrl("")).toBeTruthy();
    expect(validateProxyUrl("socks5://p:1080")).toMatch(/http/);
    expect(validateProxyUrl("http://proxy.example.org")).toMatch(/port/);
    expect(validateProxyUrl("http://proxy.example.org:3128/pac")).toMatch(/path/);
    expect(validateProxyUrl("http://u:p@proxy.example.org:3128")).toMatch(/credentials/);
    expect(validateProxyUrl("http://proxy.example.org:3128?x=1")).toMatch(/query/);
  });
});

describe("allowed hosts", () => {
  it("validates entries", () => {
    expect(validateAllowedHost("app.example.org")).toBeNull();
    expect(validateAllowedHost("*.example.org")).toBeNull();
    expect(validateAllowedHost("*")).toBeTruthy();
    expect(validateAllowedHost("*.com")).toBeTruthy();
    expect(validateAllowedHost("a*.example.org")).toBeTruthy();
    expect(validateAllowedHost("https://example.org")).toBeTruthy();
    expect(validateAllowedHost("example.org:8080")).toBeTruthy();
  });
  it("parses free text", () => {
    expect(parseHosts("A.example.org, *.b.example.org\nA.example.org  ")).toEqual(["a.example.org", "*.b.example.org"]);
  });
  it("matches exact and suffix hosts", () => {
    expect(hostMatches("app.example.org", ["app.example.org"])).toBe(true);
    expect(hostMatches("APP.example.org.", ["app.example.org"])).toBe(true);
    expect(hostMatches("x.y.example.org", ["*.example.org"])).toBe(true);
    expect(hostMatches("example.org", ["*.example.org"])).toBe(false);
    expect(hostMatches("badexample.org", ["*.example.org"])).toBe(false);
    expect(hostMatches("other.org", ["app.example.org"])).toBe(false);
  });
  it("marks proxy choices by host match", () => {
    const ps = [{ id: "1", name: "A", allowed_hosts: ["*.example.org"] }, { id: "2", name: "B", allowed_hosts: ["x.test"] }];
    expect(proxyChoices("https://app.example.org/", ps, "").map((c) => c.matches)).toEqual([true, false]);
    expect(proxyChoices("", ps, "2").map((c) => c.matches)).toEqual([true, true]);
  });
});

const vals = (o: Partial<ProxyFormValues> = {}): ProxyFormValues => ({
  name: " Squid ", url: "http://p.example.org:3128", username: "", password: "", hostsText: "*.example.org", enabled: true, ...o,
});

describe("validateProxyForm / buildProxyPayload", () => {
  it("requires name, url and at least one host", () => {
    expect(validateProxyForm(vals())).toEqual({});
    const e = validateProxyForm(vals({ name: "", url: "x", hostsText: "" }));
    expect(Object.keys(e).sort()).toEqual(["hosts", "name", "url"]);
    expect(validateProxyForm(vals({ password: "s" })).username).toBeTruthy();
  });
  it("omits blank credentials on edit (keep existing)", () => {
    const b = buildProxyPayload(vals(), true);
    expect(b).toEqual({ name: "Squid", url: "http://p.example.org:3128", allowed_hosts: ["*.example.org"], enabled: true });
    expect("password" in b).toBe(false);
    expect("username" in b).toBe(false);
  });
  it("sends typed credentials and clears on request", () => {
    expect(buildProxyPayload(vals({ username: "u", password: "p" }), true)).toMatchObject({ username: "u", password: "p" });
    expect(buildProxyPayload(vals(), true, true)).toMatchObject({ username: "", password: "" });
  });
});

describe("failure messages", () => {
  it("distinguishes the three cases", () => {
    expect(classifyEgressFailure("proxy_unreachable", true)).toBe("proxy_unreachable");
    expect(classifyEgressFailure("Could not connect to proxy: connection refused", true)).toBe("proxy_unreachable");
    expect(classifyEgressFailure("target refused via proxy (403)", true)).toBe("proxy_refused");
    expect(classifyEgressFailure("connection refused", false)).toBe("direct_unreachable");
    expect(classifyEgressFailure("connection refused", true)).toBeNull();
    expect(classifyEgressFailure("scope blocked", false)).toBeNull();
    expect(classifyEgressFailure(null, false)).toBeNull();
  });
  it("direct failures carry the PAC/WPAD hint", () => {
    const f = egressFailure("Connection refused", false)!;
    expect(f.message).toBe(DIRECT_HINT);
    expect(f.showProxyHint).toBe(true);
  });
  it("names the proxy", () => {
    expect(egressFailure("proxy_unreachable", true, "Squid")!.message).toContain('"Squid"');
  });
});
