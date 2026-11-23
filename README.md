# Sentinel Probe

A CLI application for easy security testing of web applications.

## Security checks

### Transport

| ID | Name | What it checks |
|---|---|---|
| `transport.https` | HTTPS | The target (after redirects) is served over HTTPS. |
| `transport.https-redirect` | HTTPS redirect | Plain HTTP permanently redirects (301/308) to HTTPS. |
| `transport.hsts` | HSTS | `Strict-Transport-Security` header is present with a `max-age` of at least 180 days. |
| `transport.tls-certificate` | TLS certificate | Certificate is trusted, matches the domain and is not close to expiry; obsolete TLS 1.0/1.1 are disabled. |
| `transport.mixed-content` | Mixed content | An HTTPS page does not load resources or submit forms over plain HTTP. |

### Headers

| ID | Name | What it checks |
|---|---|---|
| `headers.csp` | CSP | `Content-Security-Policy` header; warns about `'unsafe-inline'`, `'unsafe-eval'` and overly permissive sources. |
| `headers.csp-nonce` | CSP nonce | Nonces change per request, are unpredictable and present on all scripts/styles; reports inline handlers and `javascript:` links. |
| `headers.trusted-types` | Trusted Types | CSP enforces `require-trusted-types-for 'script'` against DOM XSS; warns about `'allow-duplicates'` and `*` in `trusted-types`. |
| `headers.clickjacking` | Clickjacking | The page cannot be framed by other sites (`X-Frame-Options` or CSP `frame-ancestors`). |
| `headers.content-type-options` | X-Content-Type-Options | `X-Content-Type-Options: nosniff` prevents MIME sniffing. |
| `headers.referrer-policy` | Referrer-Policy | `Referrer-Policy` limits how much of the URL is sent to other sites. |
| `headers.permissions-policy` | Permissions-Policy | `Permissions-Policy` disables unneeded browser features (camera, microphone, geolocation, …). |
| `headers.cross-origin-isolation` | Cross-Origin policies | `Cross-Origin-Opener-Policy` isolates the page from windows of other sites and `Cross-Origin-Resource-Policy` stops them from loading it as a resource; `Cross-Origin-Embedder-Policy` is reported for information. |
| `headers.cors` | CORS | The server does not allow foreign or `null` origins, especially together with credentials. |
| `headers.information-disclosure` | Information disclosure | Headers do not reveal the technology stack and versions (`X-Powered-By`, `Server`, …). |

### Session

| ID | Name | What it checks |
|---|---|---|
| `session.cookie-flags` | Session cookie | Session cookie has `HttpOnly`, `Secure` and `SameSite` flags. |
| `session.cookie-flags-other` | Cookie flags | Flags of all other cookies, including `SameSite=None` without `Secure` and `__Secure-`/`__Host-` prefixes. |
| `session.id-in-url` | Session ID in URL | Session ID is not passed in URLs, links or forms. |
| `session.strict-mode` | Session strict mode | The server rejects a made-up session ID and issues a new one (session fixation). |
| `session.cache` | Session cache | Responses setting a session cookie are not stored by shared caches. |

### Exposure

| ID | Name | What it checks |
|---|---|---|
| `exposure.sensitive-files` | Sensitive files | Exposed VCS metadata, `.env`, phpinfo, backups, database dumps, server status pages. |
| `exposure.debug-output` | Debug output | Error messages, stack traces, SQL errors and debug tools on the page and on a 404 page. |
| `exposure.directory-listing` | Directory listing | Automatically generated directory listings on the target and common directories. |
| `exposure.source-maps` | Source maps | Same-origin scripts and stylesheets do not expose their source maps (`SourceMap` header, `sourceMappingURL` comment, guessed `file.js.map`, inline maps). |
| `exposure.js-secrets` | Secrets in JavaScript | The page and same-origin scripts do not contain secret keys (AWS, Stripe, GitHub, Slack, SendGrid, OpenAI, Anthropic, Supabase `service_role`, private keys); found keys are masked. |
| `exposure.trace-method` | TRACE method | The server does not echo back `TRACE` requests (Cross-Site Tracing). |

### Content

| ID | Name | What it checks |
|---|---|---|
| `content.subresource-integrity` | Subresource Integrity | Cross-origin scripts and stylesheets have `integrity` and `crossorigin` attributes. |

## License

Sentinel Probe is **source-available** software under a dual license:

| Use | License |
|---|---|
| Noncommercial (personal, study, research, nonprofit organizations) | [PolyForm Noncommercial 1.0.0](LICENSE), free |
| Commercial (companies, freelancers, paid services) | individual terms, [contact the developer](COMMERCIAL.md#commercial-license) |

See [COMMERCIAL.md](COMMERCIAL.md) for details.

Want to contribute? Read [CONTRIBUTING.md](CONTRIBUTING.md).

## Support :]
*********************************************************
If you like the project, you can support its development with a coffee -> https://buymeacoffee.com/lukashron Thank you!
*********************************************************

Copyright (c) 2026 Lukas Hron | www.lukashron.cz | May the Force be with you.