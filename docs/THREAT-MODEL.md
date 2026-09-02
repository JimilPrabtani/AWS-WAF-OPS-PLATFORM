# Threat model

## Scope

One public, static origin behind a CDN or load balancer. No authentication, no
database, no application logic. That narrowness is deliberate: it keeps the
analysis about the WAF rather than about an imaginary application.

## What the WAF covers

| Technique | ATT&CK | Rule | Mode (prod) |
|---|---|---|---|
| Exploit public-facing application — injection | T1190 | AWSKnownBadInputs | BLOCK |
| Exploit public-facing application — Log4Shell | T1190 / CVE-2021-44228 | AWSKnownBadInputs | BLOCK |
| Active scanning — wordlist | T1595.003 | RateLimit, SuspiciousUserAgents, `scanner-sweep` detection | BLOCK / COUNT |
| Active scanning — vulnerability | T1595.002 | AWSCommonRuleSet | COUNT — *not yet promoted* |
| Endpoint DoS — application exhaustion | T1499.003 | RateLimit | BLOCK |
| Brute force — credential stuffing | T1110.004 | RateLimit + `credential-stuffing` detection | BLOCK / alert |
| Server-side request forgery | T1190 / CWE-918 | AWSKnownBadInputs | BLOCK |
| Proxy / anonymised infrastructure | T1090 | AWSAnonymousIpList | COUNT — signal only |

## What the WAF does **not** cover

Being explicit here is the point of the document.

- **Business logic abuse.** A request that is well-formed, authenticated and
  malicious in intent is indistinguishable from a legitimate one at the edge.
- **Authenticated account takeover.** WAF sees no session state.
- **CSRF.** The `OriginValidation` rule checks that state-changing requests carry
  a recognised `Origin`. That is defence in depth. Real CSRF defence is SameSite
  cookies plus server-side token validation, because only the server can bind a
  token to a session.
- **Anything past the body inspection limit.** WAFv2 inspects a bounded prefix of
  the request body. `OversizeHandling` decides what happens beyond it, and
  "CONTINUE" means the remainder is not inspected.
- **Encrypted or encoded payloads** the transformations do not normalise.
- **Anything reaching the origin directly.** This is precisely why
  `modules/static-site` exists and why `wafops verify bypass` runs in CI. In the
  prototype, this was not a theoretical gap.
- **Volumetric DDoS.** Standard Shield handles L3/L4; anything beyond that is
  Shield Advanced.
- **Sophisticated bots.** UA matching is defeated by one flag. The real answer is
  AWS Bot Control, which is a paid upgrade this project deliberately does not buy.

## Controls that are noise reduction, not security

Stated plainly so the coverage table cannot be read as more than it is:

- **GeoRestriction.** Blocking RU/CN/KP/IR measurably reduces background scanner
  volume, which is a real operational benefit. It stops no motivated attacker —
  a VPN defeats it in one click. It is here for log hygiene and, in some
  organisations, for compliance paperwork.
- **SuspiciousUserAgents.** A signal feeding `scanner-sweep`. Permanently COUNT.

## Residual risk

With `AWSCommonRuleSet` still in COUNT, generic injection shapes not covered by
`KnownBadInputs` reach the origin. Since the origin is a static bucket serving two
HTML files, the practical impact is nil — but the coverage claim is not made until
the tuning report supports promoting the group. See `docs/RULE-TUNING-REPORT.md`.
