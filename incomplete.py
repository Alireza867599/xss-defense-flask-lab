"""
Four-Task Intermediate XSS Defense Homework - Student Starter File
==================================================================

Students must complete the TODO sections in this file.
Do not add a complete.py file to the student submission.

Run the app:
    flask --app incomplete run --debug --port 5000

Run the student tests:
    python -m pytest -q tests/test_student.py
"""

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
    """TODO Task 1:
    Convert any input to safe, bounded text.

    Requirements:
    - None becomes "".
    - Non-string values are converted with str().
    - Normalize CRLF/CR to LF.
    - If multiline=False, replace newlines with spaces.
    - Remove ASCII control characters.
    - Strip leading/trailing whitespace.
    - Limit length to max_len.
    """
    # Starter implementation: intentionally incomplete.
    if value is None:
        return ""
    return str(value)[:max_len]


def html_text(value: Any) -> str:
    """TODO Task 1:
    Escape untrusted data for normal HTML text context.

    Example:
        <b>"x"</b>  ->  &lt;b&gt;"x"&lt;/b&gt;

    Hint:
        Use html.escape(..., quote=False).
    """
    # Starter implementation: unsafe, students must fix it.
    return normalize_text(value)


def html_attr(value: Any) -> str:
    """TODO Task 1:
    Escape untrusted data for quoted HTML attribute context.

    Attribute context must escape quotes. For this homework, also make sure
    event-handler-like strings cannot survive as raw attribute syntax.
    """
    # Starter implementation: unsafe, students must fix it.
    return normalize_text(value)


def safe_href(candidate: Any) -> str:
    """TODO Task 1:
    Validate and encode a URL for use inside href="...".

    Allow only:
    - http:// and https:// URLs with a host
    - mailto:user@example.com
    - local paths beginning with one slash, such as /profile

    Reject:
    - javascript:, data:, vbscript:, file:
    - protocol-relative URLs such as //evil.example
    - URLs containing spaces, quotes, angle brackets, backslashes, or control chars

    Return "#" for unsafe URLs.
    """
    # Starter implementation: unsafe, students must fix it.
    return normalize_text(candidate)


# ---------------------------------------------------------------------------
# Task 2 - Rich HTML allow-list sanitization and safe post rendering
# ---------------------------------------------------------------------------

ALLOWED_TAGS = {
    "p", "br", "b", "strong", "i", "em", "ul", "ol", "li",
    "blockquote", "code", "pre", "a",
}

ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
}

REMOVED_BLOCKS_RE = re.compile(
    r"(?is)<\s*(script|style|iframe|object|embed|svg|math)\b[^>]*>.*?<\s*/\s*\1\s*>",
)


def sanitize_rich_html(raw_html: Any) -> str:
    """TODO Task 2:
    Sanitize user-authored rich HTML with a small allow-list.

    Requirements:
    - Allow simple formatting tags such as p, strong, em, ul, ol, li, code, pre.
    - Allow a tags only with safe href/title attributes.
    - Remove script, style, iframe, object, embed, svg, and math blocks.
    - Remove javascript: and other unsafe URLs from links.

    Hint:
        Use nh3.clean(...).
    """
    # Starter implementation: unsafe, students must fix it.
    return normalize_text(raw_html, multiline=True, max_len=5000)


def render_post_card(post: Post) -> str:
    """TODO Task 2:
    Render one blog post safely.

    Required contexts:
    - title: HTML text context
    - author display text: HTML text context
    - author in title="...": HTML attribute context
    - category in data-category="...": HTML attribute context
    - website in href="...": safe URL context
    - body_html: sanitized rich HTML context
    """
    # Starter implementation: unsafe, students must fix it.
    return f"""
    <article class="post-card" data-category="{post.category}" title="Post by {post.author}">
        <h2>{post.title}</h2>
        <p>By <a href="{post.website}">{post.author}</a></p>
        <div class="post-body">{post.body_html}</div>
    </article>
    """


# ---------------------------------------------------------------------------
# Task 3 - CSP nonce, security headers, and safer cookies
# ---------------------------------------------------------------------------


def create_nonce() -> str:
    """TODO Task 3:
    Create a fresh unpredictable nonce for one HTTP response.

    Hint:
        Use secrets.token_urlsafe(...).
    """
    # Starter implementation: predictable, students must fix it.
    return "TODO_NONCE"


@app.before_request
def attach_nonce_to_request() -> None:
    g.csp_nonce = create_nonce()


@app.after_request
def apply_security_headers(response):
    """TODO Task 3:
    Add defense-in-depth headers and safer demo cookie flags.

    Requirements:
    - Content-Security-Policy with script-src 'self' and nonce
    - object-src 'none'
    - base-uri 'none'
    - frame-ancestors 'none'
    - X-Content-Type-Options: nosniff
    - Referrer-Policy: no-referrer
    - X-Frame-Options: DENY
    - Cookie lab_session with HttpOnly and SameSite=Lax
    """
    # Starter implementation: intentionally incomplete.
    response.set_cookie("lab_session", "demo-session")
    return response


# ---------------------------------------------------------------------------
# Task 4 - Safe JavaScript state and DOM XSS defense
# ---------------------------------------------------------------------------


def escape_json_for_html_script(data: Any) -> str:
    """TODO Task 4:
    Serialize JSON safely before embedding it inside a <script> block.

    Requirements:
    - Use json.dumps(...).
    - Escape <, >, &, ', U+2028, and U+2029 using Unicode escape sequences.
    - The raw string </script> must never appear inside the result.
    """
    # Starter implementation: unsafe, students must fix it.
    return json.dumps(data, ensure_ascii=False)


def render_preview_script(state: dict[str, Any], nonce: str) -> str:
    """TODO Task 4:
    Render a nonce-protected script that writes untrusted data as text.

    Requirements:
    - Use escape_json_for_html_script(state).
    - Put nonce safely in the script tag.
    - Use textContent, not innerHTML.
    """
    # Starter implementation: unsafe, students must fix it.
    return f"""
    <script nonce="{nonce}">
        window.previewState = {json.dumps(state, ensure_ascii=False)};
        document.getElementById('preview-output').innerHTML = window.previewState.message || '';
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
    return redirect("/")


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
        // TODO Task 4: replace unsafe HTML insertion with safe text insertion.
        document.getElementById('hash-output').innerHTML = hashValue || 'No hash input';
    </script>
    """

    return make_response(page("DOM", body))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
