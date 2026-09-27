🛡️ TrustScore

A lightweight Chrome extension that scores any website's security in real time — checking HTTPS, security headers, malware databases, vulnerable JavaScript libraries, and exposed secrets — then displays a live Safe / Caution / Risky badge.

Built for the IBM Bob 2.0 Hackathon.

What it does

Level 1 — Automatic (runs on every page load)

Checks whether the connection uses HTTPS
Queries the Google Safe Browsing API for known malware/phishing
Reads security response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
Inspects cookies for Secure and HttpOnly flags
Updates the toolbar badge instantly with a 0–100 trust score
Fires a browser notification if a site scores as "Risky"

Level 2 — Deep Scan (on-demand, triggered from the popup)

Detects outdated/vulnerable JS libraries (jQuery < 3.5, Angular 1.x, Bootstrap < 4)
Detects mixed content (HTTP resources on an HTTPS page)
Flags forms missing CSRF tokens
Searches for exposed API keys/secrets in the page source
Finds internal file paths leaked in HTML comments

Pre-Scan

Check any URL's safety directly from the popup, before navigating to it
How to install and test
Clone or download this repository
Open Chrome and go to chrome://extensions
Enable Developer mode (top-right toggle)
Click Load unpacked and select the project folder
The TrustScore icon appears in the toolbar — click it on any website to see the live score
Setup note — API key

The Google Safe Browsing API key is intentionally excluded from this repository for security.

To enable Safe Browsing checks:

Copy secrets.example.js to secrets.js
Add your own API key inside secrets.js

The extension works fully without a key — Safe Browsing checks are simply skipped. All other scoring signals (HTTPS, headers, cookies, vulnerable libraries, exposed secrets, CSRF, mixed content) remain fully functional.

Project structure
background.js — Service worker: scoring pipeline, badge updates, messaging
content.js — Injected script: Level 2 page scanning
popup.html / popup.js — Extension popup UI
scoring.js — Pure scoring logic
config.js — Vulnerable library definitions
secrets.example.js — API key template (see setup note above)
manifest.json — Chrome extension manifest (v3)
bob_sessions/ — IBM Bob task session summary screenshots
Built with IBM Bob IDE

All 12 development sub-tasks — from header capture and badge logic to the Level 2 deep-scan pipeline — were implemented using IBM Bob IDE's Agent mode, following a structured plan (site-trust-score-plan.md). Task session summaries are saved as screenshots in the bob_sessions/ folder as evidence of usage.
