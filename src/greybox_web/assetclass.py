"""Classify a URL path (and optional content type) as page / api / static / media / other.

Dependency-free (standard library only, no I/O) so any module may import it: the Network
map and Traffic views use it to fold build output (``/_next/static/...`` chunks, css,
fonts) away from the pages and API endpoints that matter, and the model's knowledge
snapshot can use it to keep that noise out of prompts. The web UI has a mirror of these
rules (``web/src/features/greybox/assetClass.ts``); both are tested on the same cases.

Classes:

* ``static``  build output and front-end resources: scripts, stylesheets, source maps,
              fonts, anything under a known build/asset prefix
* ``media``   images, audio, video (favicons included)
* ``api``     data endpoints: ``/api/...``, GraphQL, ``/_next/data``, JSON/XML responses
* ``page``    documents a browser would navigate to (extension-less paths, .html, .php ...)
* ``other``   everything else (robots.txt, manifests, archives, documents)

Path signals win over the content type; the content type decides only when the path is
ambiguous. A hashed file name (``main.3a6ba036.js``) is just an extension case.
"""
from __future__ import annotations

from urllib.parse import urlsplit

PAGE, API, STATIC, MEDIA, OTHER = "page", "api", "static", "media", "other"

# Prefixes that only ever hold build output / bundled assets. Longest first is not needed:
# matching is by whole path segments.
STATIC_PREFIXES: tuple[str, ...] = (
    "/_next/static", "/_next/image", "/_nuxt", "/_app/immutable", "/_astro", "/_assets",
    "/static", "/assets", "/build", "/dist", "/bundles", "/public", "/resources/static",
    "/wp-content", "/wp-includes", "/sites/default/files", "/media/cache",
    "/webpack", "/__webpack_hmr", "/cdn-cgi/scripts",
)
API_PREFIXES: tuple[str, ...] = (
    "/api", "/graphql", "/gql", "/rest", "/trpc", "/rpc", "/_next/data", "/odata",
    "/jsonrpc", "/ajax", "/wp-json",
)
STATIC_EXT = frozenset({"js", "mjs", "cjs", "css", "map", "woff", "woff2", "ttf", "otf", "eot",
                        "wasm", "scss", "less"})
MEDIA_EXT = frozenset({"png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp", "tif",
                       "tiff", "apng", "heic", "mp3", "mp4", "webm", "ogg", "wav", "m4a", "mov",
                       "avi", "mkv", "flac"})
PAGE_EXT = frozenset({"html", "htm", "xhtml", "php", "asp", "aspx", "jsp", "jspx", "do",
                      "action", "cfm", "shtml", "cgi", "pl"})
API_EXT = frozenset({"json", "xml", "rss", "atom", "graphql"})

# Well-known files that are neither pages nor data endpoints.
OTHER_NAMES = frozenset({"robots.txt", "sitemap.xml", "sitemap.xml.gz", "manifest.json",
                         "site.webmanifest", "manifest.webmanifest", "humans.txt",
                         "security.txt", "browserconfig.xml", "ads.txt", "crossdomain.xml"})


def _path_of(url: str) -> str:
    """The path of a URL or bare path; query and fragment dropped, never raises."""
    if not url:
        return "/"
    s = url.strip()
    try:
        path = urlsplit(s).path if "://" in s or s.startswith("//") else s.split("#", 1)[0].split("?", 1)[0]
    except ValueError:
        path = s.split("#", 1)[0].split("?", 1)[0]
    return path if path.startswith("/") else "/" + path


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _ext(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    if "." not in name.strip("."):
        return ""
    return name.rsplit(".", 1)[-1]


def _mime(content_type: str | None) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def classify_path(url: str, content_type: str | None = None) -> str:
    """``"page" | "api" | "static" | "media" | "other"`` for a URL or path."""
    path = _path_of(url).lower()
    name = path.rsplit("/", 1)[-1]
    ext = _ext(path).lower()
    mime = _mime(content_type)

    if _under(path, "/_next/image"):
        return MEDIA
    if any(_under(path, p) for p in STATIC_PREFIXES):
        return MEDIA if ext in MEDIA_EXT else STATIC
    if ext in STATIC_EXT:
        return STATIC
    if ext in MEDIA_EXT:
        return MEDIA
    if name in OTHER_NAMES or _under(path, "/.well-known"):
        return OTHER
    if any(_under(path, p) for p in API_PREFIXES):
        return API
    if ext in PAGE_EXT:
        return PAGE
    if ext in API_EXT:
        return API

    # Ambiguous path (no telling extension): the content type decides.
    if mime:
        if mime in ("text/css", "text/javascript", "application/javascript", "application/x-javascript",
                    "application/ecmascript", "application/wasm", "application/font-woff",
                    "application/vnd.ms-fontobject") or mime.startswith("font/"):
            return STATIC
        if mime.startswith(("image/", "audio/", "video/")):
            return MEDIA
        if mime in ("text/html", "application/xhtml+xml"):
            return PAGE
        if (mime.endswith("json") or mime.endswith("+xml") or mime in ("application/xml", "text/xml")
                or mime in ("application/x-ndjson", "application/grpc", "application/graphql",
                            "text/event-stream", "application/problem+json")):
            return API
        if mime == "text/plain" and not ext:
            return OTHER if name else PAGE
        if mime in ("application/octet-stream", "application/pdf", "application/zip",
                    "application/gzip", "text/csv"):
            return OTHER
    if ext:
        return OTHER
    return PAGE


def is_static_like(cls: str) -> bool:
    """True for the classes folded away by default (build output and media)."""
    return cls in (STATIC, MEDIA)


def static_prefix(url: str) -> str:
    """The folding group of a static asset: the known build prefix it sits under
    (``/_next/static``, ``/static`` ...), else its first directory, else ``/`` for root files."""
    path = _path_of(url)
    low = path.lower()
    for p in STATIC_PREFIXES:
        if _under(low, p):
            return path[: len(p)]
    segs = [s for s in path.split("/") if s]
    return "/" + segs[0] if len(segs) > 1 else "/"
