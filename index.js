#!/usr/bin/env node

'use strict';

const https = require('https');
const http = require('http');
const url = require('url');

// ─── Header Definitions ───────────────────────────────────────────────────────

const HEADERS = [
  {
    key: 'strict-transport-security',
    label: 'Strict-Transport-Security',
    check(val) {
      if (!val) return { status: 'red', note: 'MISSING' };
      const maxAge = val.match(/max-age=(\d+)/i);
      const age = maxAge ? parseInt(maxAge[1], 10) : 0;
      if (age >= 31536000 && /includesubdomains/i.test(val)) {
        return { status: 'green', note: val };
      }
      if (age >= 86400) {
        return { status: 'yellow', note: `${val} (max-age low or missing includeSubDomains)` };
      }
      return { status: 'red', note: `${val} (max-age too low)` };
    },
    fix: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
  },
  {
    key: 'content-security-policy',
    label: 'Content-Security-Policy',
    check(val) {
      if (!val) return { status: 'red', note: 'MISSING' };
      if (/unsafe-inline|unsafe-eval|\*/i.test(val)) {
        return { status: 'yellow', note: 'present but permissive (unsafe-inline / wildcard)' };
      }
      return { status: 'green', note: val.length > 80 ? val.slice(0, 77) + '...' : val };
    },
    fix: "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
  },
  {
    key: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    check(val) {
      if (!val) return { status: 'red', note: 'MISSING' };
      if (val.trim().toLowerCase() === 'nosniff') return { status: 'green', note: val };
      return { status: 'yellow', note: `${val} (expected: nosniff)` };
    },
    fix: 'X-Content-Type-Options: nosniff',
  },
  {
    key: 'x-frame-options',
    label: 'X-Frame-Options',
    check(val) {
      if (!val) return { status: 'red', note: 'MISSING' };
      const upper = val.trim().toUpperCase();
      if (upper === 'DENY' || upper === 'SAMEORIGIN') return { status: 'green', note: val };
      return { status: 'yellow', note: `${val} (use DENY or SAMEORIGIN)` };
    },
    fix: 'X-Frame-Options: DENY',
  },
  {
    key: 'x-xss-protection',
    label: 'X-XSS-Protection',
    check(val) {
      if (!val) return { status: 'yellow', note: 'MISSING (deprecated but still checked by scanners)' };
      return { status: 'green', note: `${val} (deprecated — CSP replaces this)` };
    },
    fix: 'X-XSS-Protection: 1; mode=block',
  },
  {
    key: 'referrer-policy',
    label: 'Referrer-Policy',
    check(val) {
      if (!val) return { status: 'red', note: 'MISSING' };
      const strict = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade'];
      const policies = val.split(',').map(p => p.trim().toLowerCase());
      if (policies.some(p => strict.includes(p))) return { status: 'green', note: val };
      return { status: 'yellow', note: `${val} (prefer strict-origin-when-cross-origin)` };
    },
    fix: 'Referrer-Policy: strict-origin-when-cross-origin',
  },
  {
    key: 'permissions-policy',
    label: 'Permissions-Policy',
    check(val) {
      if (!val) return { status: 'red', note: 'MISSING' };
      const blocks = ['camera=()', 'microphone=()', 'geolocation=()'];
      const allBlocked = blocks.every(b => val.includes(b));
      if (allBlocked) return { status: 'green', note: val.length > 80 ? val.slice(0, 77) + '...' : val };
      return { status: 'yellow', note: 'present but camera/mic/geo may not be blocked' };
    },
    fix: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  },
  {
    key: 'cross-origin-opener-policy',
    label: 'Cross-Origin-Opener-Policy (COOP)',
    check(val) {
      if (!val) return { status: 'red', note: 'MISSING' };
      if (/same-origin/i.test(val)) return { status: 'green', note: val };
      return { status: 'yellow', note: `${val} (prefer same-origin)` };
    },
    fix: 'Cross-Origin-Opener-Policy: same-origin',
  },
  {
    key: 'cross-origin-resource-policy',
    label: 'Cross-Origin-Resource-Policy (CORP)',
    check(val) {
      if (!val) return { status: 'red', note: 'MISSING' };
      if (/same-origin|same-site/i.test(val)) return { status: 'green', note: val };
      return { status: 'yellow', note: `${val} (prefer same-origin or same-site)` };
    },
    fix: 'Cross-Origin-Resource-Policy: same-origin',
  },
  {
    key: 'cross-origin-embedder-policy',
    label: 'Cross-Origin-Embedder-Policy (COEP)',
    check(val) {
      if (!val) return { status: 'red', note: 'MISSING' };
      if (/require-corp/i.test(val)) return { status: 'green', note: val };
      return { status: 'yellow', note: `${val} (prefer require-corp)` };
    },
    fix: 'Cross-Origin-Embedder-Policy: require-corp',
  },
];

// ─── Grading ──────────────────────────────────────────────────────────────────

function grade(results) {
  // Green = 1 pt, Yellow = 0.5 pt, Red = 0 pt. X-XSS-Protection is worth 0 (deprecated).
  let score = 0;
  let max = 0;
  for (const r of results) {
    const isDeprecated = r.key === 'x-xss-protection';
    if (isDeprecated) continue; // exclude from scoring
    max += 1;
    if (r.status === 'green') score += 1;
    else if (r.status === 'yellow') score += 0.5;
  }

  const pct = score / max;
  let letter, label;

  if (pct >= 1.0)        { letter = 'A+'; label = 'Fort Knox'; }
  else if (pct >= 0.85)  { letter = 'A';  label = 'Solid security posture'; }
  else if (pct >= 0.70)  { letter = 'B';  label = 'Good but gaps remain'; }
  else if (pct >= 0.50)  { letter = 'C';  label = 'Below average'; }
  else if (pct >= 0.25)  { letter = 'D';  label = 'Needs serious work'; }
  else                   { letter = 'F';  label = 'Wide open. Deploy a WAF immediately.'; }

  const greenCount = results.filter(r => r.status === 'green').length;
  return { letter, label, score, max, pct, greenCount, total: results.length };
}

// ─── HTTP Fetch ───────────────────────────────────────────────────────────────

function fetchHeaders(rawUrl, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('Too many redirects'));

    let parsed;
    try {
      parsed = new url.URL(rawUrl);
    } catch {
      return reject(new Error(`Invalid URL: ${rawUrl}`));
    }

    const lib = parsed.protocol === 'https:' ? https : http;

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'HEAD',
      headers: {
        'User-Agent': 'security-header-check/1.0 (github.com/NickCirv/security-header-check)',
      },
    };

    const req = lib.request(options, (res) => {
      const loc = res.headers['location'];
      if ((res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) && loc) {
        const next = loc.startsWith('http') ? loc : `${parsed.origin}${loc}`;
        return resolve(fetchHeaders(next, redirects + 1));
      }
      resolve({ headers: res.headers, statusCode: res.statusCode, finalUrl: rawUrl });
    });

    req.on('error', reject);

    req.setTimeout(10000, () => {
      req.destroy(new Error('Request timed out after 10s'));
    });

    req.end();
  });
}

// ─── Display ──────────────────────────────────────────────────────────────────

const ICONS = { green: '\u2705', yellow: '\u26A0\uFE0F ', red: '\u274C' };
const COLORS = {
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  red:    '\x1b[31m',
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  cyan:   '\x1b[36m',
};

function colorize(status, text) {
  return `${COLORS[status]}${text}${COLORS.reset}`;
}

function pad(str, len) {
  return str + ' '.repeat(Math.max(0, len - str.length));
}

function printResults(targetUrl, results, gradeInfo) {
  const { letter, label, greenCount, total } = gradeInfo;

  console.log('');
  console.log(`${COLORS.bold}${COLORS.cyan}\uD83D\uDD12 SECURITY HEADER CHECK${COLORS.reset}`);
  console.log('\u2501'.repeat(40));
  console.log('');
  console.log(`${COLORS.bold}URL:${COLORS.reset}   ${targetUrl}`);
  console.log(`${COLORS.bold}Grade:${COLORS.reset} ${colorize(letter === 'F' || letter === 'D' ? 'red' : letter === 'C' ? 'yellow' : 'green', `${letter}`)}  ${COLORS.dim}${label}${COLORS.reset}  ${COLORS.dim}(${greenCount}/${total} headers passing)${COLORS.reset}`);
  console.log('');

  const labelWidth = Math.max(...results.map(r => r.label.length)) + 2;

  for (const r of results) {
    const icon = ICONS[r.status];
    const lbl = pad(r.label, labelWidth);
    const note = r.status === 'red'
      ? colorize('red', r.note)
      : r.status === 'yellow'
        ? colorize('yellow', r.note)
        : COLORS.dim + r.note + COLORS.reset;
    console.log(`  ${icon} ${colorize(r.status === 'red' ? 'red' : r.status === 'yellow' ? 'yellow' : 'green', lbl)}  ${note}`);
  }

  const missing = results.filter(r => r.status === 'red' && r.fix);
  const weak    = results.filter(r => r.status === 'yellow' && r.fix);

  if (missing.length || weak.length) {
    console.log('');
    if (missing.length) {
      console.log(`${COLORS.bold}Missing headers \u2014 add these:${COLORS.reset}`);
      for (const r of missing) {
        console.log(`  ${COLORS.dim}${r.fix}${COLORS.reset}`);
      }
    }
    if (weak.length) {
      console.log(`${COLORS.bold}Weak headers \u2014 consider hardening:${COLORS.reset}`);
      for (const r of weak) {
        if (r.status === 'yellow' && r.key !== 'x-xss-protection') {
          console.log(`  ${COLORS.dim}${r.fix}${COLORS.reset}`);
        }
      }
    }
  }

  console.log('');
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function run() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  const rawUrl = args.find(a => !a.startsWith('--'));

  if (!rawUrl) {
    console.error('Usage: security-header-check <url> [--json]');
    console.error('Example: security-header-check https://example.com');
    process.exit(1);
  }

  const target = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`;

  let response;
  try {
    response = await fetchHeaders(target);
  } catch (err) {
    console.error(`\u274C  Failed to fetch ${target}: ${err.message}`);
    process.exit(1);
  }

  const { headers, statusCode, finalUrl } = response;

  const results = HEADERS.map(h => {
    const val = headers[h.key] || null;
    const { status, note } = h.check(val);
    return {
      key: h.key,
      label: h.label,
      status,
      note,
      value: val,
      fix: h.fix,
      present: !!val,
    };
  });

  const gradeInfo = grade(results);

  if (jsonMode) {
    const out = {
      url: finalUrl,
      statusCode,
      grade: gradeInfo.letter,
      label: gradeInfo.label,
      score: gradeInfo.score,
      maxScore: gradeInfo.max,
      headers: results.map(r => ({
        name: r.label,
        key: r.key,
        status: r.status,
        value: r.value,
        note: r.note,
        recommendation: r.status !== 'green' ? r.fix : null,
      })),
    };
    console.log(JSON.stringify(out, null, 2));
    process.exit(gradeInfo.letter === 'A+' || gradeInfo.letter === 'A' ? 0 : 1);
  }

  printResults(finalUrl, results, gradeInfo);
  process.exit(gradeInfo.letter === 'A+' || gradeInfo.letter === 'A' ? 0 : 1);
}

run().catch(err => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
