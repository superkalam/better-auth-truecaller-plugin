# Plugin Design Notes

Unlike `better-auth-phone`, this plugin has **no upstream counterpart** in the
better-auth core library. It is an original implementation.

This document describes the architectural decisions, external API contracts, and
known limitations to help contributors understand why the code is shaped the way
it is.

---

## What this plugin does

TrueCaller provides two verification flows depending on platform:

- **Android** — OAuth 2.0 authorization code flow. The mobile SDK obtains an
  authorization code; the plugin exchanges it for an access token, then fetches
  the user profile from TrueCaller's `/userinfo` endpoint.

- **iOS** — Signed payload flow. The mobile SDK produces a signed JSON payload
  and a detached signature; the plugin fetches TrueCaller's RSA public keys,
  verifies the signature, and extracts the identity from the payload.

Both flows produce a normalized `TruecallerNormalizedIdentity` (countryCode +
phoneNumber + optional name/image), which is then used to find or create a
Better Auth user.

---

## External API contracts

### Android OAuth endpoints (region-dependent)

| Region | OAuth base URL |
|--------|---------------|
| `global` | `https://oauth-account-noneu.truecaller.com` |
| `eu` | `https://oauth-account.truecaller.com` |

Endpoints used:
- `POST /v1/token` — exchange authorization code for access token
- `GET /v1/userinfo` — fetch user profile using the access token

### iOS public key endpoint

`GET https://api4.truecaller.com/v1/key`

Returns an array of `{ keyType, key }` objects. Only RSA keys are used.
Keys are cached in memory with a configurable TTL (default 5 minutes) to
avoid fetching on every request.

### Signature algorithms

TrueCaller iOS SDK reports the signature algorithm in a Java-style name.
The plugin maps these to Node.js `crypto` names:

| TrueCaller name | Node.js name |
|-----------------|--------------|
| `SHA256withRSA` | `RSA-SHA256` |
| `SHA384withRSA` | `RSA-SHA384` |
| `SHA512withRSA` | `RSA-SHA512` |

If the algorithm is unknown or absent, both `RSA-SHA512` and `RSA-SHA256` are
tried in that order.

---

## Phone identity normalization (`utils.ts`)

TrueCaller's API is inconsistent across SDK versions and platforms:

| Platform | Phone field | Country code field | Country code format |
|----------|-------------|-------------------|---------------------|
| Android | `phoneNumber` or `phone_number` | `phone_number_country_code` | ISO alpha-2 (e.g. `"IN"`) |
| iOS | `phoneNumber` | `countryCode` (inside payload) | Numeric dial code (e.g. `"91"`) |

The `normalizeTruecallerIdentity` function handles all variations:

1. Tries a list of known field names for the phone value.
2. If the country code looks like ISO alpha-2 (`/^[A-Z]{2}$/i`), converts it
   to a dial code using the built-in `ISO_TO_DIAL_CODE` map (200+ countries).
3. If it looks like a digit string, uses it directly as a dial code.
4. If no country code is present, falls back to a heuristic: assumes the local
   number is 10 digits and everything before it is the country code.

The `ISO_TO_DIAL_CODE` map is self-contained in `utils.ts` and covers all
countries where TrueCaller operates. It replaces any app-level validator that
only supported a small set of countries.

---

## User lookup and creation

Users are looked up by `(phoneNumber, countryCode)` — the same composite key
used by `better-auth-phone`. This means both plugins can coexist on the same
user table without conflict.

If a user is found but `phoneNumberVerified` is `false` (e.g. registered via
another flow), TrueCaller verification marks them as verified.

If no user is found and `signUpOnVerification` is not configured, the endpoint
throws `UNAUTHORIZED`. Auto-signup must be explicitly enabled.

---

## In-memory public key cache

The iOS public key cache (`publicKeyCache`) is module-level state shared across
all requests in the same process. The cache stores the fetched keys and a
timestamp; it is invalidated after `publicKeyCacheTTLMs` milliseconds (default
5 minutes).

This is safe for server deployments. In serverless/edge environments where each
invocation gets a fresh module context, the cache provides no benefit but causes
no harm — it will simply re-fetch on every cold start.

---

## Better Auth integration

### Imports

| Symbol | Source |
|--------|--------|
| `createAuthEndpoint` | `@better-auth/core/api` |
| `createAuthMiddleware` | `@better-auth/core/api` |
| `APIError` | `better-call` — NOT `@better-auth/core/error`. `APIError` is originally defined in `better-call` and re-exported by better-auth. Import it from the source to avoid resolution issues across better-auth versions. |
| `BASE_ERROR_CODES` | `@better-auth/core/error` |
| `setSessionCookie` | `better-auth/cookies` |
| `mergeSchema` | `better-auth/db` |
| `BetterAuthPlugin`, `BetterAuthClientPlugin` | `better-auth` / `@better-auth/core` |

### Plugin ID

Server: `"better-auth-truecaller"`
Client: `"betterAuthTruecaller"`

### Inferred client methods

Because `$InferServerPlugin` points at the server plugin, Better Auth's client
type inference exposes:

- `authClient.truecaller.verifyAndroid({ authorizationCode, codeVerifier? })`
- `authClient.truecaller.verifyIos({ payload, signature, requestNonce, signatureAlgorithm? })`

The method names are derived from the endpoint paths (`/truecaller/verify-android`,
`/truecaller/verify-ios`), not from the endpoint key names in the plugin object.

### Rate limiting

10 requests per 60 seconds per IP on all `/truecaller/*` paths.
`rateLimit.window` is in **seconds** — better-auth's rate limiter multiplies by
1000 internally.

---

## Known limitations

### No CSRF protection on Android flow

The Android OAuth flow does not validate a state parameter. TrueCaller's Android
SDK does not expose the OAuth state to the app. If your threat model requires
CSRF protection for the token exchange, you should add a nonce/state at the
application layer (e.g. store a short-lived token in your own session and verify
it before calling this endpoint).

### iOS nonce is caller-supplied

The `requestNonce` is provided by the client in the request body and must match
the value embedded in the TrueCaller-signed payload. The plugin verifies this
match, but it relies on TrueCaller's signature to ensure the nonce in the
payload was not tampered with. Do not reuse nonces across requests.

### Composite uniqueness

The `phoneNumber` column is declared `unique: true` at the column level in the
schema. If you need the same local number to exist under different country codes,
replace the single-column constraint with a composite index after migration:

```sql
ALTER TABLE "user" DROP CONSTRAINT "user_phoneNumber_unique";
CREATE UNIQUE INDEX "user_phone_country_unique" ON "user" ("phoneNumber", "countryCode");
```
