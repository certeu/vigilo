// Mirror of src/greybox_web/assetclass.py (keep the two in step; both are tested on the same
// table). Classifies a URL path as page / api / static / media / other so the Network map and
// the Traffic tab can fold build output (/_next/static chunks, css, fonts) away by default.
// Pure, no dependencies.

export type AssetClass = "page" | "api" | "static" | "media" | "other";

const STATIC_PREFIXES = [
  "/_next/static", "/_next/image", "/_nuxt", "/_app/immutable", "/_astro", "/_assets",
  "/static", "/assets", "/build", "/dist", "/bundles", "/public", "/resources/static",
  "/wp-content", "/wp-includes", "/sites/default/files", "/media/cache",
  "/webpack", "/__webpack_hmr", "/cdn-cgi/scripts",
];
const API_PREFIXES = ["/api", "/graphql", "/gql", "/rest", "/trpc", "/rpc", "/_next/data", "/odata", "/jsonrpc", "/ajax", "/wp-json"];
const set = (s: string) => new Set(s.split(" "));
const STATIC_EXT = set("js mjs cjs css map woff woff2 ttf otf eot wasm scss less");
const MEDIA_EXT = set("png jpg jpeg gif webp avif svg ico bmp tif tiff apng heic mp3 mp4 webm ogg wav m4a mov avi mkv flac");
const PAGE_EXT = set("html htm xhtml php asp aspx jsp jspx do action cfm shtml cgi pl");
const API_EXT = set("json xml rss atom graphql");
const OTHER_NAMES = set("robots.txt sitemap.xml sitemap.xml.gz manifest.json site.webmanifest manifest.webmanifest humans.txt security.txt browserconfig.xml ads.txt crossdomain.xml");
const STATIC_MIME = set("text/css text/javascript application/javascript application/x-javascript application/ecmascript application/wasm application/font-woff application/vnd.ms-fontobject");
const API_MIME = set("application/xml text/xml application/x-ndjson application/grpc application/graphql text/event-stream");
const OTHER_MIME = set("application/octet-stream application/pdf application/zip application/gzip text/csv");

/** Path of a URL or bare path (query and fragment dropped); never throws. */
export function pathOf(url: string | null | undefined): string {
  const s = (url ?? "").trim();
  if (!s) return "/";
  let path: string;
  const m = /^(?:[a-z][a-z0-9+.-]*:)?\/\/[^/?#]*([^?#]*)/i.exec(s);
  if (m) path = m[1];
  else path = s.split("#", 1)[0].split("?", 1)[0];
  return path.startsWith("/") ? path : `/${path}`;
}

const under = (path: string, prefix: string) => path === prefix || path.startsWith(`${prefix}/`);

function extOf(path: string): string {
  const name = path.slice(path.lastIndexOf("/") + 1);
  const bare = name.replace(/^\.+|\.+$/g, "");
  return bare.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : "";
}

export function classifyPath(url: string | null | undefined, contentType?: string | null): AssetClass {
  const path = pathOf(url).toLowerCase();
  const name = path.slice(path.lastIndexOf("/") + 1);
  const ext = extOf(path);
  const mime = (contentType ?? "").split(";", 1)[0].trim().toLowerCase();

  if (under(path, "/_next/image")) return "media";
  if (STATIC_PREFIXES.some((p) => under(path, p))) return MEDIA_EXT.has(ext) ? "media" : "static";
  if (STATIC_EXT.has(ext)) return "static";
  if (MEDIA_EXT.has(ext)) return "media";
  if (OTHER_NAMES.has(name) || under(path, "/.well-known")) return "other";
  if (API_PREFIXES.some((p) => under(path, p))) return "api";
  if (PAGE_EXT.has(ext)) return "page";
  if (API_EXT.has(ext)) return "api";

  if (mime) {
    if (STATIC_MIME.has(mime) || mime.startsWith("font/")) return "static";
    if (/^(image|audio|video)\//.test(mime)) return "media";
    if (mime === "text/html" || mime === "application/xhtml+xml") return "page";
    if (mime.endsWith("json") || mime.endsWith("+xml") || API_MIME.has(mime)) return "api";
    if (mime === "text/plain" && !ext) return name ? "other" : "page";
    if (OTHER_MIME.has(mime)) return "other";
  }
  return ext ? "other" : "page";
}

/** Static assets and media: the classes folded away by default. */
export const isStaticLike = (c: AssetClass): boolean => c === "static" || c === "media";

/** Folding group of a static asset: its known build prefix, else its first directory, else "/". */
export function staticPrefix(url: string | null | undefined): string {
  const path = pathOf(url);
  const low = path.toLowerCase();
  for (const p of STATIC_PREFIXES) if (under(low, p)) return path.slice(0, p.length);
  const segs = path.split("/").filter(Boolean);
  return segs.length > 1 ? `/${segs[0]}` : "/";
}

/** "/_next/static — 143 files, 2.1 MB" (size omitted when unknown). */
export function groupLabel(prefix: string, files: number, bytes: number | null, host?: string): string {
  const where = prefix === "/" ? (host ? "/ (root files)" : "root files") : prefix;
  const size = bytes && bytes > 0 ? `, ${formatBytes(bytes)}` : "";
  return `${host ?? ""}${where} — ${files} file${files === 1 ? "" : "s"}${size}`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
