"""Static-asset classifier shared by the Network map, Traffic view and the model snapshot.
The same table is mirrored in web/src/features/greybox/assetClass.test.ts."""
import pytest

from src.greybox_web.assetclass import classify_path, is_static_like, static_prefix

CASES = [
    # Next.js build output (the real target)
    ("https://app.example.test:443/_next/static/chunks/3442c0ffbdab5fa6.js", None, "static"),
    ("/_next/static/chunks/d2a6f830a0f357e6.css", "text/css", "static"),
    ("/_next/static/media/83afe278b6a6bb3c-s.p.3a6ba036.woff2", None, "static"),
    ("/_next/static/abc123/_buildManifest.js", None, "static"),
    ("/_next/image?url=%2Flogo.png&w=64&q=75", "image/webp", "media"),
    ("/_next/data/abc123/notebooks.json", "application/json", "api"),
    # conventional asset directories and extensions
    ("/static/app.js", None, "static"),
    ("/assets/index-4f9a1c.js", None, "static"),
    ("/assets/logo.svg", None, "media"),
    ("/dist/main.3a6ba036.css", None, "static"),
    ("/js/jquery.min.js?v=3", None, "static"),
    ("/app.js.map", None, "static"),
    ("/fonts/inter.woff2", None, "static"),
    ("/wp-content/uploads/a.jpg", None, "media"),
    ("/favicon.ico", None, "media"),
    ("/favicon.ico?favicon.0b3bf435.ico", None, "media"),
    ("/img/hero.PNG", None, "media"),
    ("/video/intro.mp4", None, "media"),
    # pages
    ("/", "text/html; charset=utf-8", "page"),
    ("/notebooks", None, "page"),
    ("/login", "text/html", "page"),
    ("/index.html", None, "page"),
    ("/admin/index.php", None, "page"),
    ("https://example.test/a/b/", None, "page"),
    # api
    ("/api/users", None, "api"),
    ("/api/v1/items/1", "application/json", "api"),
    ("/graphql", None, "api"),
    ("/v2/things", "application/json; charset=utf-8", "api"),
    ("/feed", "application/vnd.api+json", "api"),
    ("/data.json", None, "api"),
    ("/thing", "application/xml", "api"),
    ("/api/avatar.png", None, "media"),
    # content type decides on ambiguous paths
    ("/bundle", "application/javascript", "static"),
    ("/logo", "image/png", "media"),
    ("/font", "font/woff2", "static"),
    # other
    ("/robots.txt", "text/plain", "other"),
    ("/sitemap.xml", "application/xml", "other"),
    ("/manifest.json", "application/json", "other"),
    ("/.well-known/security.txt", None, "other"),
    ("/report.pdf", None, "other"),
    ("/backup.zip", None, "other"),
    # robustness
    ("", None, "page"),
    ("not a url ::: %zz", None, "page"),
    ("http://[::1", None, "page"),
]


@pytest.mark.parametrize("url,ct,want", CASES)
def test_classify(url, ct, want):
    assert classify_path(url, ct) == want


def test_path_signal_beats_content_type():
    assert classify_path("/static/app.js", "text/html") == "static"
    assert classify_path("/login", "application/javascript") == "static"  # ambiguous path: type decides


def test_is_static_like():
    assert is_static_like("static") and is_static_like("media")
    assert not any(is_static_like(c) for c in ("page", "api", "other"))


@pytest.mark.parametrize("url,want", [
    ("https://h:443/_next/static/chunks/a.js", "/_next/static"),
    ("/_next/static/media/f.woff2", "/_next/static"),
    ("/static/js/a.js", "/static"),
    ("/Assets/a.js", "/Assets"),
    ("/favicon.ico", "/"),
    ("/vendor/lib/x.js", "/vendor"),
])
def test_static_prefix(url, want):
    assert static_prefix(url) == want
