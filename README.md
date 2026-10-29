# xss-defense-flask-lab-Copy
A Python Flask security project exploring Cross-Site Scripting (XSS) prevention through context-aware encoding, HTML sanitization, CSP, secure headers, and DOM protection. Copy description


# XSS Defense Lab with Python and Flask

A hands-on web security project focused on understanding and preventing **Cross-Site Scripting (XSS)** in a small Flask application. The lab demonstrates how untrusted input can become dangerous when inserted into HTML, URLs, JavaScript, or the DOM, and explores the defensive techniques used to handle that input safely.

This repository is based on a four-task intermediate network/web security homework assignment. It includes a starter application with deliberately unfinished security functions and a separate implementation of the defensive features.

> **Educational use only:** Run this application locally. It is a learning exercise, not a production-ready web application or a complete security assessment.

## Objectives

- Use context-aware output encoding for HTML text and attributes.
- Validate links and reject unsafe URL schemes.
- Sanitize user-provided rich HTML with an allow-list.
- Apply Content Security Policy (CSP), nonces, security headers, and safer cookie settings.
- Prevent DOM-based XSS by handling dynamic content as text rather than executable HTML.
- Verify defenses through automated tests and manual browser checks.

## The four tasks

### Task 1 — Context-aware encoding and URL validation

Implement input normalization and safe output handling:

- `normalize_text()` — normalize and bound text input.
- `html_text()` — escape strings used as HTML text.
- `html_attr()` — escape strings used in quoted HTML attributes.
- `safe_href()` — allow suitable `http`, `https`, `mailto`, and local-path URLs while rejecting dangerous or malformed values.

### Task 2 — Rich HTML sanitization and safe post rendering

Use **nh3** to preserve a limited set of formatting tags without allowing executable markup. Safely render blog-post titles, authors, website links, categories, and sanitized post bodies through `sanitize_rich_html()` and `render_post_card()`.

### Task 3 — CSP, response headers, and cookies

Generate an unpredictable per-request nonce and configure defense-in-depth protections, including:

- Content-Security-Policy with nonce-based script authorization.
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: no-referrer`.
- `X-Frame-Options: DENY`.
- A demo session cookie with `HttpOnly` and `SameSite=Lax` (the provided completed file also sets `Secure`).

### Task 4 — Safe JavaScript state and DOM XSS prevention

Safely serialize state for an HTML `<script>` block, use nonce-protected scripts, and insert untrusted content with `textContent` instead of `innerHTML`. The `/preview` and `/dom` pages demonstrate these techniques.

## Technology stack

- **Python** — application logic and security utilities.
- **Flask** — HTTP routes and request/response hooks.
- **nh3** — allow-list HTML sanitization.
- **pytest** — automated verification (when the assignment's test file is available).
- **HTML / JavaScript** — browser-side behavior and DOM handling.

## Repository structure

Rename the supplied files to these clean names before uploading:

```text
xss-defense-flask-lab/
├── README.md
├── complete.py          # Implemented security-demo Flask app
├── incomplete.py        # Original student starter with TODOs
├── requirements.txt     # Flask, nh3, pytest
└── assignment.pdf       # Four-task homework handout (optional)
```

The homework handout also refers to `tests/test_student.py`, but that test file was **not included among the files provided for this repository**. If you have it and are permitted to share it, you can add it under `tests/`.

## Installation

**Prerequisite:** Python 3.10+ is recommended.

1. Clone the repository and move into its directory:

   ```bash
   git clone https://github.com/YOUR_USERNAME/xss-defense-flask-lab.git
   cd xss-defense-flask-lab
   ```

2. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

3. Activate it:

   **macOS / Linux**

   ```bash
   source .venv/bin/activate
   ```

   **Windows PowerShell**

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

## Running the application

### Completed implementation

After renaming `complete(7).py` to `complete.py`:

```bash
python complete.py
```

Open **http://127.0.0.1:5001/**. The supplied completed file starts Flask on port `5001` with debug mode enabled, so use it **only in a local development environment**.

### Starter application

After renaming the supplied starter file to `incomplete.py`:

```bash
flask --app incomplete run --debug --port 5000
```

Open **http://127.0.0.1:5000/**. The starter intentionally contains unfinished and unsafe code. Do not treat it as a secure deployment.

## Demo routes

| Route | Purpose |
| --- | --- |
| `/` | Create and view rich-text blog posts |
| `/post` | Submit a blog post |
| `/search?q=...` | Demonstrate safe rendering of search text |
| `/profile?name=...&website=...` | Demonstrate HTML encoding and URL validation |
| `/preview?message=...` | Demonstrate safer JavaScript state embedding |
| `/dom#...` | Demonstrate safe handling of URL hash content in the DOM |
| `/api/posts` | Retrieve demo posts as JSON |

Posts are held **in memory** and are lost when the app restarts.

## Testing and verification

The assignment specifies two kinds of verification:

1. **Automated tests:** The handout expects a `tests/test_student.py` file that imports `incomplete.py`. If you have that file and have completed the student functions in `incomplete.py`, run:

   ```bash
   python -m pytest -q tests/test_student.py
   ```

   The expected homework result is four passing tests. **This README does not claim the tests were run or passed**; the test file was not among the uploaded files.

2. **Manual browser checks:** Confirm that HTML-like input is displayed as text where appropriate, unsafe profile links are rejected, sanitized blog posts retain only allowed formatting, response headers contain the expected protections, CSP nonces change across requests, and `/preview` plus `/dom` avoid HTML interpretation of untrusted text.

Example local checks (for the completed app on port 5001):

```text
http://127.0.0.1:5001/search?q=%3Cb%3Ehello%3C%2Fb%3E
http://127.0.0.1:5001/profile?name=Student&website=javascript:alert(1)
http://127.0.0.1:5001/preview?message=%3Cb%3Ehello%3C%2Fb%3E
http://127.0.0.1:5001/dom#%3Cb%3Ehello%3C%2Fb%3E
```

In these checks, untrusted markup should not become executable HTML. Also inspect response headers in your browser's developer tools.

## Notes and limitations

- This is a **teaching demo**; it does not include authentication, a database, persistent storage, or production deployment configuration.
- The provided completed code contains a post-submission redirect to `"+"` in `create_post_route()`. If the intended behavior is to return to the home page, change that line to `return redirect("/")` before publishing.
- A browser can enforce the `Secure` cookie attribute differently on local HTTP versus production HTTPS. Use HTTPS for any real deployment.
- The handout says student submissions should contain the completed `incomplete.py`, not an instructor solution file. Confirm you are allowed to publicly publish any completed or reference implementation before pushing it to GitHub.

## Learning outcomes

This lab provides practical experience with **XSS prevention, secure HTML rendering, browser security policies, safe DOM APIs, and Flask request/response handling**. Its central lesson is that input validation alone is insufficient: data must be handled safely for the *specific output context* in which it is used.

## References

- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Flask documentation](https://flask.palletsprojects.com/)
- [pytest documentation](https://docs.pytest.org/)

---

**Disclaimer:** For educational demonstrations and authorized local security testing only.
