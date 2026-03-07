# 🔒 security-header-check

[![npm version](https://img.shields.io/npm/v/security-header-check.svg)](https://www.npmjs.com/package/security-header-check)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D14-brightgreen.svg)](https://nodejs.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-blue.svg)](https://www.npmjs.com/package/security-header-check)

> Zero-dependency Node.js CLI that audits HTTP security headers for any URL — with traffic-light scoring, grade A–F, and exact fix instructions.

```
🔒 SECURITY HEADER CHECK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

URL:   https://example.com
Grade: B  Good but gaps remain  (6/10 headers passing)

  ✅ Strict-Transport-Security            max-age=31536000; includeSubDomains
  ✅ X-Content-Type-Options               nosniff
  ✅ X-Frame-Options                      SAMEORIGIN
  ⚠️  Content-Security-Policy             present but permissive (unsafe-inline)
  ❌ Permissions-Policy                   MISSING
  ❌ Referrer-Policy                      MISSING
  ✅ Cross-Origin-Opener-Policy (COOP)    same-origin

Missing headers — add these:
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
  Referrer-Policy: strict-origin-when-cross-origin
```

---

## Install

### Global (recommended)

```bash
npm install -g security-header-check
```

### Run without installing

```bash
npx security-header-check https://yoursite.com
```

---

## Usage

```bash
# Basic check
security-header-check https://example.com

# Skip https:// — it's assumed
security-header-check example.com

# JSON output for CI/CD pipelines
security-header-check https://example.com --json
```

---

## Headers Checked

| Header | What it does |
|--------|-------------|
| `Strict-Transport-Security` | Forces HTTPS, prevents downgrade attacks |
| `Content-Security-Policy` | Controls resource loading, prevents XSS |
| `X-Content-Type-Options` | Stops MIME sniffing |
| `X-Frame-Options` | Prevents clickjacking |
| `X-XSS-Protection` | Legacy XSS filter (deprecated, still scanned) |
| `Referrer-Policy` | Controls referrer header leakage |
| `Permissions-Policy` | Locks camera, mic, geolocation access |
| `Cross-Origin-Opener-Policy` | Isolates browsing context from cross-origin |
| `Cross-Origin-Resource-Policy` | Prevents cross-origin resource reads |
| `Cross-Origin-Embedder-Policy` | Enables cross-origin isolation |

---

## Grade Table

| Grade | Score | Label |
|-------|-------|-------|
| **A+** | 10/10 | Fort Knox |
| **A**  | 8–9  | Solid security posture |
| **B**  | 6–7  | Good but gaps remain |
| **C**  | 4–5  | Below average |
| **D**  | 2–3  | Needs serious work |
| **F**  | 0–1  | Wide open. Deploy a WAF immediately. |

---

## CI/CD Integration

Use `--json` for machine-readable output. Exit code is `0` for A/A+, `1` for anything lower.

```yaml
# GitHub Actions example
- name: Security header audit
  run: npx security-header-check https://yoursite.com --json
```

```json
{
  "url": "https://example.com",
  "grade": "B",
  "label": "Good but gaps remain",
  "score": 6.5,
  "maxScore": 9,
  "headers": [
    {
      "name": "Strict-Transport-Security",
      "key": "strict-transport-security",
      "status": "green",
      "value": "max-age=31536000; includeSubDomains",
      "note": "max-age=31536000; includeSubDomains",
      "recommendation": null
    }
  ]
}
```

---

## Traffic Light Logic

- **Green** — header present and correctly configured
- **Yellow** — present but weak, permissive, or deprecated
- **Red** — missing entirely

X-XSS-Protection is included in the output (many scanners still flag it) but excluded from the grade score since it's deprecated and CSP replaces it.

---

## You Might Also Like

### Cirv Guard — WordPress Security Plugin

Running WordPress? Check out **[Cirv Guard](https://cirvgreen.com/products/cirv-guard)** — a lightweight WordPress plugin that adds and manages all these security headers automatically, with one click.

Available free on [WordPress.org](https://wordpress.org/plugins/cirv-guard/).

---

More tools by **[github.com/NickCirv](https://github.com/NickCirv)**:

- [schema-or-die](https://github.com/NickCirv/schema-or-die) — Schema.org audit CLI
- [robots-txt-audit](https://github.com/NickCirv/robots-txt-audit) — robots.txt linter

---

## License

MIT — Nicholas Ashkar / [cirvgreen.com](https://cirvgreen.com)

## Contributing

PRs welcome! If you have a funny idea or improvement:

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing-idea`)
3. Commit your changes
4. Push to the branch (`git push origin feature/amazing-idea`)
5. Open a Pull Request

Found a bug? [Open an issue](https://github.com/NickCirv/security-header-check/issues).

---

If this made you mass-exhale through your nose, mass-hit that star button.
