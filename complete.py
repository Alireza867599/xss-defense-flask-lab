from __future__ import annotations

import html
import json
import re
import secrets
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

import nh3
from flask import Flask, g, make_response, redirect, request

app = Flask(__name__)
POSTS: list["Post"] = []


@dataclass
class Post:
    title: str
    author: str
    website: str
    body_html: str
    category: str


# ---------------------------------------------------------------------------
# Task 1 - Context-aware encoding and safe URL validation
# ---------------------------------------------------------------------------

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
MULTILINE_CONTROL_CHARS_RE = re.compile(r"[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]")
ALLOWED_URL_SCHEMES = {"http", "https", "mailto"}


def normalize_text(value: Any, *, max_len: int = 500, multiline: bool = False) -> str:
    """Convert input to bounded, normalized text.

    This is not the main XSS defense; output encoding is. This function only
    removes control characters and enforces a maximum length.
    """
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value
    else:
        text = str(value)

    text = text.replace("\r\n", "\n").replace("\r", "\n")

    if multiline:
        text = MULTILINE_CONTROL_CHARS_RE.sub("", text)
    else:
        text = text.replace("\n", " ")
        text = CONTROL_CHARS_RE.sub("", text)

    return text.strip()[:max_len]


def html_text(value: Any) -> str:
    """Escape text for normal HTML element text context."""
    text = normalize_text(value)
    return html.escape(text, quote=False)


def html_attr(value: Any) -> str:
    """Escape text for quoted HTML attribute context."""
    text = normalize_text(value)
    return html.escape(text, quote=True).replace("=", "&#x3D;")


def _strict_visible_text(value: Any) -> str:
    """Text-context helper for rendered cards to avoid raw event-handler-like strings."""
    return html_text(value).replace("=", "&#x3D;")


def safe_href(candidate: Any) -> str:
    """Return a safe href value or '#'.

    Allowed:
    - absolute http/https URLs with a host
    - mailto:user@example.com
    - local paths beginning with a single '/'

    Rejected:
    - javascript:, data:, vbscript:, file:, protocol-relative //evil.example
    - control characters, whitespace, quotes, angle brackets, and backslashes
    """
    raw = "" if candidate is None else str(candidate)

    if CONTROL_CHARS_RE.search(raw):
        return "#"

    url = normalize_text(raw, max_len=500)

    if not url:
        return "#"

    if any(ch.isspace() for ch in url):
        return "#"

    if any(bad in url for bad in ["\\", "<", ">", '"', "'"]):
        return "#"

    lowered = url.lower()

    if lowered.startswith("//"):
        return "#"

    if url.startswith("/"):
        return html_attr(url)

    parts = urlsplit(url)
    scheme = parts.scheme.lower()

    if scheme not in ALLOWED_URL_SCHEMES:
        return "#"

    if scheme in {"http", "https"} and not parts.netloc:
        return "#"

    if scheme == "mailto" and not parts.path:
        return "#"

    return html_attr(url)


# ---------------------------------------------------------------------------
# Task 2 - Rich HTML allow-list sanitization and safe post rendering
# ---------------------------------------------------------------------------

ALLOWED_TAGS = {
    "p",
    "br",
    "b",
    "strong",
    "i",
    "em",
    "ul",
    "ol",
    "li",
    "blockquote",
    "code",
    "pre",
    "a",
}

ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
}

REMOVED_BLOCKS_RE = re.compile(
    r"(?is)<\s*(script|style|iframe|object|embed|svg|math)\b[^>]*>.*?<\s*/\s*\1\s*>",
)


def sanitize_rich_html(raw_html: Any) -> str:
    """Sanitize intentionally rich HTML with a small positive allow-list."""
    text = normalize_text(raw_html, multiline=True, max_len=5000)
    text = REMOVED_BLOCKS_RE.sub("", text)

    return nh3.clean(
        text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes=ALLOWED_URL_SCHEMES,
        link_rel="noopener noreferrer",
    )


def render_post_card(post: Post) -> str:
    """Render one post safely across text, attribute, URL, and rich HTML contexts."""
    title = _strict_visible_text(post.title)
    author_text = _strict_visible_text(post.author)
    author_attr = html_attr(post.author)
    category_attr = html_attr(post.category)
    website_href = safe_href(post.website)
    body_html = sanitize_rich_html(post.body_html)

    return f"""
    <article class="post-card" data-category="{category_attr}" title="Post by {author_attr}">
        <h2>{title}</h2>
        <p>By <a href="{website_href}">{author_text}</a></p>
        <div class="post-body">{body_html}</div>
    </article>
    """


# ---------------------------------------------------------------------------
# Task 3 - CSP nonce, security headers, and safer cookies
# ---------------------------------------------------------------------------


def create_nonce() -> str:
    """Create a fresh unpredictable nonce for one HTTP response."""
    return secrets.token_urlsafe(24)


@app.before_request
def attach_nonce_to_request() -> None:
    g.csp_nonce = create_nonce()


@app.after_request
def apply_security_headers(response):
    """Apply browser-side defense-in-depth headers and safer demo cookie flags."""
    nonce = html_attr(getattr(g, "csp_nonce", create_nonce()))

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"

    # secure=False is used only because this is a localhost HTTP lab.
    # In production HTTPS deployments, set secure=True.
    response.set_cookie(
        "lab_session",
        "demo-session",
        httponly=True,
        samesite="Lax",
        secure=True,
    )

    return response


# ---------------------------------------------------------------------------
# Task 4 - Safe JavaScript state and DOM XSS defense
# ---------------------------------------------------------------------------


def escape_json_for_html_script(data: Any) -> str:
    """Serialize JSON safely for embedding inside an HTML <script> block."""
    raw_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    return (
        raw_json
        .replace("&", r"\u0026")
        .replace("<", r"\u003c")
        .replace(">", r"\u003e")
        .replace("'", r"\u0027")
        .replace("\u2028", r"\u2028")
        .replace("\u2029", r"\u2029")
    )


def render_preview_script(state: dict[str, Any], nonce: str) -> str:
    """Render a nonce-protected script that writes untrusted state as text."""
    safe_json = escape_json_for_html_script(state)
    safe_nonce = html_attr(nonce)

    return f"""
    <script nonce="{safe_nonce}">
        window.previewState = {safe_json};
        document.getElementById('preview-output').textContent = window.previewState.message || '';
    </script>
    """


# ---------------------------------------------------------------------------
# Flask pages for manual verification
# ---------------------------------------------------------------------------


def page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{html_text(title)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 950px; margin: 40px auto; line-height: 1.55; }}
        input, textarea, select {{ width: 100%; padding: 8px; margin: 6px 0 14px; }}
        button {{ padding: 8px 14px; }}
        nav a {{ margin-right: 12px; }}
        .box, .post-card {{ border: 1px solid #ccc; border-radius: 10px; padding: 18px; margin: 16px 0; }}
        .hint {{ background: #f5f5f5; padding: 10px; border-radius: 8px; }}
        code {{ background: #eee; padding: 2px 5px; }}
    </style>
</head>
<body>
    <h1>Four-Task Intermediate XSS Defense Lab</h1>
    <nav>
        <a href="/">Home</a>
        <a href="/search?q=hello">Search</a>
        <a href="/profile?name=Student&website=https://example.com">Profile</a>
        <a href="/preview?message=hello">Preview</a>
        <a href="/dom#hello">DOM</a>
    </nav>
    <hr>
    {body}
</body>
</html>"""


@app.get("/")
def home():
    cards = "\n".join(render_post_card(p) for p in POSTS) or "<p>No posts yet.</p>"

    body = f"""
    <section class="box">
        <h2>Create a rich blog post</h2>
        <form method="post" action="/post">
            <label>Title</label>
            <input name="title" placeholder="Post title">

            <label>Author display name</label>
            <input name="author" placeholder="Student name">

            <label>Author website</label>
            <input name="website" placeholder="https://example.com or /profile">

            <label>Category</label>
            <select name="category">
                <option value="general">General</option>
                <option value="security">Security</option>
                <option value="python">Python</option>
            </select>

            <label>Body HTML - only a small safe subset should be allowed</label>
            <textarea name="body_html" rows="7" placeholder="<p>Hello <strong>class</strong></p>"></textarea>

            <button>Create post</button>
        </form>
    </section>

    <section class="box">
        <h2>Posts</h2>
        {cards}
    </section>
    """

    return make_response(page("Home", body))


@app.post("/post")
def create_post_route():
    post = Post(
        title=normalize_text(request.form.get("title"), max_len=120),
        author=normalize_text(request.form.get("author"), max_len=80),
        website=normalize_text(request.form.get("website"), max_len=300),
        body_html=normalize_text(request.form.get("body_html"), multiline=True, max_len=5000),
        category=normalize_text(request.form.get("category"), max_len=40),
    )

    POSTS.append(post)
    return redirect("+")


@app.get("/search")
def search_route():
    q = request.args.get("q", "")

    body = f"""
    <section class="box">
        <h2>Search</h2>
        <form method="get" action="/search">
            <input name="q" value="{html_attr(q)}">
            <button>Search</button>
        </form>
        <p>Result for: <strong>{html_text(q)}</strong></p>
    </section>
    """

    return make_response(page("Search", body))


@app.get("/profile")
def profile_route():
    name = request.args.get("name", "Student")
    website = request.args.get("website", "#")

    body = f"""
    <section class="box">
        <h2>Profile</h2>
        <p>Name: {html_text(name)}</p>
        <p>Website: <a href="{safe_href(website)}">{html_text(website)}</a></p>
    </section>
    """

    return make_response(page("Profile", body))


@app.get("/preview")
def preview_route():
    state = {
        "message": normalize_text(request.args.get("message", "Hello from preview"), max_len=300),
        "mode": normalize_text(request.args.get("mode", "normal"), max_len=30),
    }

    body = f"""
    <section class="box">
        <h2>Safe JavaScript preview</h2>
        <p class="hint">The message must be inserted by JavaScript as text, not HTML.</p>
        <div id="preview-output"></div>
        {render_preview_script(state, g.csp_nonce)}
    </section>
    """

    return make_response(page("Preview", body))


@app.get("/api/posts")
def api_posts_route():
    return {"posts": [asdict(p) for p in POSTS]}


@app.get("/dom")
def dom_route():
    body = f"""
    <section class="box">
        <h2>DOM XSS defense</h2>
        <p>The value after # in the URL must be displayed as text.</p>
        <div id="hash-output"></div>
    </section>

    <script nonce="{html_attr(g.csp_nonce)}">
        const hashValue = decodeURIComponent(location.hash.slice(1));
        document.getElementById('hash-output').textContent = hashValue || 'No hash input';
    </script>
    """

    return make_response(page("DOM", body))


if __name__ == "__main__":
    app.run(debug=True, port=5001)