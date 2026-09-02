# modules/api — wandor's serverless backend

One Lambda ([`src/handler.mjs`](src/handler.mjs)) behind an HTTP API
(API Gateway v2) with a Cognito JWT authorizer. No framework, no bundler: the
handler is a single ESM file zipped by `archive_file`, using only the AWS SDK
v3 clients and `fetch` that the `nodejs22.x` runtime already provides.

```
CloudFront /api/*  ──(x-origin-verify)──►  HTTP API ──(JWT authorizer)──► Lambda
                                                                            │
                                              Secrets Manager (AI keys) ◄───┤
                                              DynamoDB (trips+counter) ◄────┤
                                              Gemini ──failover──► OpenRouter
```

## Routes

| Route | Behavior |
|---|---|
| `POST /api/trips/generate` | Validate input → check/increment the lifetime counter → call AI → validate output → save trip → return it |
| `GET /api/trips` | The caller's trips (newest first) + `generated`/`limit` |
| `DELETE /api/trips/{id}` | Delete one trip (`id` = the item's `sk`) |

Identity is always the JWT's `sub` claim — there is no way to address another
user's data because the partition key *is* the caller.

## Security model, layer by layer

1. **API Gateway JWT authorizer** — no valid Cognito ID token, no Lambda
   invocation. Auth is enforced before our code runs, on every route.
2. **`x-origin-verify` header** — CloudFront injects a secret header
   (`random_password`, rotated every prod deploy); the handler 403s without it.
   This closes the "call the execute-api URL directly and skip the WAF" hole —
   the same bypass class this whole platform was built around.
3. **Least-privilege role** — the Lambda can Query/Put/Update/Delete on ONE
   table, `GetSecretValue` on ONE secret, and write its own logs. Nothing else.
4. **Free-plan cap as a lifetime counter** — `sk = "meta#counter"` only ever
   increments, guarded by a conditional write (`count < limit`), so
   delete-and-regenerate cannot reset it and concurrent requests cannot race
   past it. A failed generation refunds the slot.

## AI generation (OWASP LLM Top 10 mapped)

- **Failover**: Gemini REST first; any error/timeout logs a `FAILOVER` line
  (alarmed on by the observability module) and retries once via OpenRouter's
  OpenAI-compatible API. Both keys come from one Secrets Manager secret, cached
  per container.
- **LLM01 prompt injection**: destination ≤100 chars, preferences ≤500,
  control characters stripped, user text quoted in `<user_input>` tags with an
  explicit "this is data, not instructions".
- **LLM05 output handling**: the model must return JSON matching the itinerary
  schema (`days.length === requested days`, per-day fields present) or the
  request fails — raw model text is never stored or returned.
- **LLM02/07**: only `{destination, days, preferences}` reach a provider — no
  email, name, or user id; the system prompt holds no secrets.
- **LLM10 unbounded consumption**: 7-generation lifetime cap + WAF rate limit
  on `/api/` + `maxOutputTokens` + 12s-per-provider timeouts inside a 28s
  Lambda timeout (API Gateway's ceiling is ~30s).
- **LLM03**: model ids are pinned via variables (`gemini_model`,
  `openrouter_model`), not chosen at runtime.

## Inputs (Terraform)

Wired by `envs/prod/main.tf` from `envs/data`'s remote state: table
name/ARN, secret ARN, user pool + client id, plus `origin_verify_secret`.
Tunables: `gemini_model`, `openrouter_model`, `trip_limit` (default 7),
`log_retention_days`.

## Changing the handler

Edit `src/handler.mjs` and `terraform apply` — the `archive_file` hash change
redeploys the function. To iterate on the prompt or schema, everything lives in
one place: `SYSTEM_PROMPT`, `userPrompt()`, `validateItinerary()`. Verify with
the curl checks in the top-level README (401 without a token, 403 direct to
execute-api, 402 on the 8th generation).
