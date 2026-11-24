# Sentinel Probe

A CLI application for easy security testing of web applications.

## Security checks

Every check ends with one of these results:

| Result | Meaning |
|---|---|
| `OK` | The check passed. |
| `WARN` | A weakness or a missing hardening, not directly exploitable. |
| `FAIL` | A vulnerability or a serious misconfiguration; the scan exits with a non-zero code. |
| `SKIP` | The check does not apply to the target (e.g. no session cookie, no GraphQL endpoint) and counts neither as passed nor as failed. |

### Transport

| ID | Name | What it checks |
|---|---|---|
| `transport.https` | HTTPS | The target (after redirects) is served over HTTPS. |
| `transport.https-redirect` | HTTPS redirect | Plain HTTP permanently redirects (301/308) to HTTPS. |
| `transport.hsts` | HSTS | `Strict-Transport-Security` header is present with a `max-age` of at least 180 days and `includeSubDomains`; with `preload`, the preload list requirements are verified. |
| `transport.tls-certificate` | TLS certificate | Certificate is trusted, matches the domain and is not close to expiry; obsolete TLS 1.0/1.1 are disabled. |
| `transport.mixed-content` | Mixed content | An HTTPS page does not load resources or submit forms over plain HTTP. |

### Headers

| ID | Name | What it checks |
|---|---|---|
| `headers.csp` | CSP | All enforced policies (every header, comma-separated policies, `<meta http-equiv>`); warns about `'unsafe-inline'`, `'unsafe-eval'`, permissive sources (`*`, `https:`, `data:`, `blob:`, `filesystem:`), CSP bypass hosts (Google APIs, cdnjs, jsDelivr, unpkg, …), missing `object-src` and `base-uri`. |
| `headers.csp-nonce` | CSP nonce | Nonces change per request, are unpredictable and present on all scripts/styles; reports inline handlers and `javascript:` links. |
| `headers.trusted-types` | Trusted Types | CSP enforces `require-trusted-types-for 'script'` against DOM XSS; warns about `'allow-duplicates'` and `*` in `trusted-types`. |
| `headers.clickjacking` | Clickjacking | The page cannot be framed by other sites (`X-Frame-Options` or CSP `frame-ancestors`, which is ignored in `<meta>`). |
| `headers.content-type-options` | X-Content-Type-Options | `X-Content-Type-Options: nosniff` prevents MIME sniffing. |
| `headers.xss-protection` | X-XSS-Protection | The obsolete `X-XSS-Protection` header is missing or `0`; `1; mode=block` enables the XSS auditor abusable for XS-Leaks, `report=` sends page content away. |
| `headers.referrer-policy` | Referrer-Policy | `Referrer-Policy` limits how much of the URL is sent to other sites. |
| `headers.permissions-policy` | Permissions-Policy | `Permissions-Policy` disables unneeded browser features (camera, microphone, geolocation, …). |
| `headers.cross-origin-isolation` | Cross-Origin policies | `Cross-Origin-Opener-Policy` isolates the page from windows of other sites and `Cross-Origin-Resource-Policy` stops them from loading it as a resource; `Cross-Origin-Embedder-Policy` is reported for information. |
| `headers.reporting` | Reporting | Informative: violation reporting via `Reporting-Endpoints`/`Report-To`, CSP `report-to`/`report-uri` and COOP/COEP `report-to`; notes undefined groups and plain HTTP endpoints. |
| `headers.cors` | CORS | The server does not allow foreign or `null` origins nor origin validation bypasses (`target.com.evil.example`, `eviltarget.com`, `http://target.com`), especially together with credentials. |
| `headers.information-disclosure` | Information disclosure | Headers do not reveal the technology stack and internals (`X-Powered-By`, `Server`, `X-Generator`, `X-Drupal-*`, `X-Runtime`, `Via`, `Server-Timing`, …); `X-Debug-Token` (Symfony profiler in production) fails. |

### Session

| ID | Name | What it checks |
|---|---|---|
| `session.cookie-flags` | Session cookie | Session and authentication cookies (PHPSESSID, JSESSIONID, `auth`/`token`/JWT cookies, remember-me, Supabase, Auth0, NextAuth, …) have `HttpOnly`, `Secure` and `SameSite` (Lax or Strict); warns about `Domain=`, suggests the `__Host-` prefix. |
| `session.cookie-flags-other` | Cookie flags | Flags of all other cookies, including `SameSite=None` without `Secure`, `__Secure-`/`__Host-` prefixes, `Domain=` of a parent domain and `Partitioned` (CHIPS). |
| `session.id-in-url` | Session ID in URL | Session ID is not passed in URLs, links or forms. |
| `session.strict-mode` | Session strict mode | Native PHP sessions only: the server rejects a made-up session ID and issues a new one (session fixation). |
| `session.cache` | Session cache | Responses setting a session cookie are not stored by shared caches. |

### Exposure

| ID | Name | What it checks |
|---|---|---|
| `exposure.sensitive-files` | Sensitive files | Exposed VCS metadata, `.env`, phpinfo, backups, database dumps, server status pages, `composer.json`/`composer.lock`, `package.json`, `.npmrc`, `.aws/credentials`, `docker-compose.yml`, `web.config`, `.idea/`, `.vscode/sftp.json`, Laravel logs. |
| `exposure.framework-endpoints` | Framework endpoints | Spring Boot Actuator (`/actuator/env`, `/actuator/heapdump`), Laravel Telescope, Horizon and Ignition, Symfony profiler, Rails routes, ELMAH, Werkzeug console, Adminer and phpMyAdmin are not public. |
| `exposure.debug-output` | Debug output | Error messages, stack traces, SQL errors and debug tools on the page and on a 404 page. |
| `exposure.dev-server` | Dev server | No frontend development server runs in production: Vite, webpack-dev-server/HMR, Next.js development mode, React Refresh, `ng serve` (page markers and `/@vite/client`, `/__webpack_hmr`, `/_next/webpack-hmr`). |
| `exposure.directory-listing` | Directory listing | Automatically generated directory listings on the target and common directories. |
| `exposure.source-maps` | Source maps | Same-origin scripts and stylesheets do not expose their source maps (`SourceMap` header, `sourceMappingURL` comment, guessed `file.js.map`, inline maps). |
| `exposure.js-secrets` | Secrets in JavaScript | The page and same-origin scripts do not contain secret keys (AWS, Stripe, GitHub, Slack, SendGrid, OpenAI, Anthropic, Supabase `service_role`, private keys); found keys are masked. |
| `exposure.hydration-data` | Hydration data | Server-rendered state (`__NEXT_DATA__`, `__NUXT__`, Redux/Apollo state, Remix context, Angular TransferState) contains no passwords, hashes, secrets, tokens, database URLs or SSNs; warns about internal URLs and payloads over 200 kB. |
| `exposure.trace-method` | TRACE method | The server does not echo back `TRACE` requests (Cross-Site Tracing). |

### Content

| ID | Name | What it checks |
|---|---|---|
| `content.subresource-integrity` | Subresource Integrity | Cross-origin scripts and stylesheets have `integrity` and `crossorigin` attributes. |
| `content.vulnerable-libraries` | Vulnerable libraries | Versions of jQuery, jQuery UI, Bootstrap, AngularJS, Lodash, Moment, Handlebars and DOMPurify detected from script URLs and license banners have no known CVEs; unmaintained libraries are a warning. |

### API

| ID | Name | What it checks |
|---|---|---|
| `api.graphql` | GraphQL | A GraphQL endpoint (`/graphql`, `/api/graphql`, …) has introspection, field suggestions, batching and GET queries disabled (read-only queries only). |
| `api.documentation` | API documentation | OpenAPI/Swagger specifications (`/swagger.json`, `/openapi.json`, `/v3/api-docs`, …), Swagger UI and ReDoc are not public. |
| `api.jwt` | JWT | Tokens in cookies, headers and the page: no `alg: none`, no weak HMAC secret, an expiration of at most 30 days, no sensitive data in the payload. |
| `api.http-methods` | HTTP methods | `OPTIONS` on the page and a static file does not allow WebDAV or file modifying methods, `PROPFIND` does not reveal WebDAV (read-only requests only). |
| `api.oidc` | OpenID Connect | OIDC/OAuth discovery documents offer no implicit or password grant, advertise PKCE with `S256` and use HTTPS endpoints. |

### Domain

| ID | Name | What it checks |
|---|---|---|
| `domain.security-txt` | security.txt | `/.well-known/security.txt` (RFC 9116) exists, is `text/plain` over HTTPS and has valid `Contact` and `Expires` fields. |
| `domain.caa` | CAA | DNS CAA records limit the certificate authorities allowed to issue certificates. |
| `domain.email-spoofing` | Email spoofing | A single SPF record ending with `~all`/`-all` and DMARC with `p=quarantine` or `p=reject`. |
| `domain.subdomain-takeover` | Subdomain takeover | CNAMEs of the target host and its `www.` variant do not point to unclaimed cloud resources (S3, Heroku, Azure, GitHub Pages, Shopify, …). |

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