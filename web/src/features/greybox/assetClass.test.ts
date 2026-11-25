import { describe, expect, it } from "vitest";
import { classifyPath, groupLabel, isStaticLike, pathOf, staticPrefix, type AssetClass } from "./assetClass";

// Same table as tests/greybox_web/test_assetclass.py.
const CASES: Array<[string, string | null, AssetClass]> = [
  ["https://app.example.test:443/_next/static/chunks/3442c0ffbdab5fa6.js", null, "static"],
  ["/_next/static/chunks/d2a6f830a0f357e6.css", "text/css", "static"],
  ["/_next/static/media/83afe278b6a6bb3c-s.p.3a6ba036.woff2", null, "static"],
  ["/_next/static/abc123/_buildManifest.js", null, "static"],
  ["/_next/image?url=%2Flogo.png&w=64&q=75", "image/webp", "media"],
  ["/_next/data/abc123/notebooks.json", "application/json", "api"],
  ["/static/app.js", null, "static"],
  ["/assets/index-4f9a1c.js", null, "static"],
  ["/assets/logo.svg", null, "media"],
  ["/dist/main.3a6ba036.css", null, "static"],
  ["/js/jquery.min.js?v=3", null, "static"],
  ["/app.js.map", null, "static"],
  ["/fonts/inter.woff2", null, "static"],
  ["/wp-content/uploads/a.jpg", null, "media"],
  ["/favicon.ico", null, "media"],
  ["/favicon.ico?favicon.0b3bf435.ico", null, "media"],
  ["/img/hero.PNG", null, "media"],
  ["/video/intro.mp4", null, "media"],
  ["/", "text/html; charset=utf-8", "page"],
  ["/notebooks", null, "page"],
  ["/login", "text/html", "page"],
  ["/index.html", null, "page"],
  ["/admin/index.php", null, "page"],
  ["https://example.test/a/b/", null, "page"],
  ["/api/users", null, "api"],
  ["/api/v1/items/1", "application/json", "api"],
  ["/graphql", null, "api"],
  ["/v2/things", "application/json; charset=utf-8", "api"],
  ["/feed", "application/vnd.api+json", "api"],
  ["/data.json", null, "api"],
  ["/thing", "application/xml", "api"],
  ["/api/avatar.png", null, "media"],
  ["/bundle", "application/javascript", "static"],
  ["/logo", "image/png", "media"],
  ["/font", "font/woff2", "static"],
  ["/robots.txt", "text/plain", "other"],
  ["/sitemap.xml", "application/xml", "other"],
  ["/manifest.json", "application/json", "other"],
  ["/.well-known/security.txt", null, "other"],
  ["/report.pdf", null, "other"],
  ["/backup.zip", null, "other"],
  ["", null, "page"],
];

describe("classifyPath", () => {
  it.each(CASES)("%s (%s) -> %s", (url, ct, want) => expect(classifyPath(url, ct)).toBe(want));
  it("lets the path beat the content type", () => {
    expect(classifyPath("/static/app.js", "text/html")).toBe("static");
  });
  it("folds static and media only", () => {
    expect(["static", "media"].every((c) => isStaticLike(c as AssetClass))).toBe(true);
    expect(["page", "api", "other"].some((c) => isStaticLike(c as AssetClass))).toBe(false);
  });
});

describe("staticPrefix / labels", () => {
  it("groups by the known build prefix", () => {
    expect(staticPrefix("https://h:443/_next/static/chunks/a.js")).toBe("/_next/static");
    expect(staticPrefix("/_next/static/media/f.woff2")).toBe("/_next/static");
    expect(staticPrefix("/Assets/a.js")).toBe("/Assets");
    expect(staticPrefix("/favicon.ico")).toBe("/");
    expect(staticPrefix("/vendor/lib/x.js")).toBe("/vendor");
  });
  it("labels a group", () => {
    expect(groupLabel("/_next/static", 143, 2.1 * 1024 * 1024)).toBe("/_next/static — 143 files, 2.1 MB");
    expect(groupLabel("/", 1, null)).toBe("root files — 1 file");
  });
  it("extracts paths from urls", () => {
    expect(pathOf("https://h:443/a/b?x=1#y")).toBe("/a/b");
    expect(pathOf("a/b")).toBe("/a/b");
  });
});
