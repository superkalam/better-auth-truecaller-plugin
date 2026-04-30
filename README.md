# better-auth-truecaller

[Better Auth](https://better-auth.com) plugin for Truecaller authentication.

Verifies Truecaller identity on your server and creates a Better Auth session. Supports both platforms:

- **Android** — exchanges the OAuth 2.0 authorization code (+ optional PKCE verifier) for a user profile via Truecaller's token and userinfo endpoints
- **iOS** — verifies the signed payload using Truecaller's public keys, checks the request nonce, and extracts the user profile

## Installation

```bash
npm install github:superkalam/better-auth-truecaller-plugin#v1.0.0
# or
yarn add github:superkalam/better-auth-truecaller-plugin#v1.0.0
```

Peer dependency: `better-auth >= 1.6.0`

## Server setup

```ts
import { betterAuth } from "better-auth";
import { truecaller } from "better-auth-truecaller";

export const auth = betterAuth({
  plugins: [
    truecaller({
      clientId: process.env.TRUECALLER_CLIENT_ID!,

      // Auto-create user on first login
      signUpOnVerification: {
        getTempEmail: (phone) => `${phone}@placeholder.invalid`,
      },
    }),
  ],
});
```

## Client setup

```ts
import { createAuthClient } from "better-auth/client";
import { truecallerClient } from "better-auth-truecaller/client";

export const authClient = createAuthClient({
  plugins: [truecallerClient()],
});
```

## API endpoints

Both endpoints create a Better Auth session and set the session cookie on success.

### Android — `POST /truecaller/verify-android`

```ts
const response = await authClient.truecaller.verifyAndroid({
  authorizationCode: "...", // from Truecaller Android SDK
  codeVerifier: "...",      // PKCE verifier (optional)
});
```

Flow: `authorizationCode` → Truecaller token endpoint (`/v1/token`) → Truecaller userinfo endpoint (`/v1/userinfo`) → user lookup/creation → session.

### iOS — `POST /truecaller/verify-ios`

```ts
const response = await authClient.truecaller.verifyIos({
  payload: "...",             // signed payload from TrueSDK
  signature: "...",           // base64 signature
  requestNonce: "...",        // nonce from TrueSDK
  signatureAlgorithm: "...",  // optional
});
```

Flow: fetch Truecaller public keys → verify signature → parse payload → check nonce → user lookup/creation → session.

## Configuration

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `clientId` | `string` | ✅ | — | Truecaller client ID from developer console |
| `region` | `"global" \| "eu"` | — | `"global"` | Routes to EU or non-EU Truecaller endpoints |
| `signUpOnVerification` | `object` | — | — | Auto-create user on first login |
| `signUpOnVerification.getTempEmail` | `(phone) => string` | ✅ if signUp | — | Returns a temporary email for the new user (full phone number passed: e.g. `"919876543210"`) |
| `signUpOnVerification.getTempName` | `(phone) => string` | — | Truecaller name → phone | Returns a temporary display name |
| `onVerificationSuccess` | `(data, ctx) => void` | — | — | Called after identity is verified, before user lookup/creation |
| `callbackAfterVerification` | `(data, ctx) => void` | — | — | Called after the user is found or created |
| `onLoginSuccess` | `(data, ctx) => Promise<Record<string, unknown>>` | — | — | Inject additional data into the login response. See below. |
| `oauthBaseUrl` | `string` | — | region default | Override Truecaller OAuth base URL |
| `verificationBaseUrl` | `string` | — | region default | Override Truecaller verification base URL |
| `publicKeyUrl` | `string` | — | `https://api4.truecaller.com/v1/key` | Override Truecaller public key URL |
| `upstreamTimeoutMs` | `number` | — | `15000` | HTTP timeout for Truecaller API calls |
| `publicKeyCacheTTLMs` | `number` | — | `300000` | In-memory public key cache TTL (iOS only) |
| `schema` | `object` | — | — | Remap DB column names |

---

## Injecting additional data into the login response (`onLoginSuccess`)

Use `onLoginSuccess` to fetch additional data on the server and return it in the same
login response — eliminating a client round-trip.

**Timing:** the hook is called **before the session is created**, running in parallel
with `createSession`. This means:
- No extra latency — it overlaps with the session write.
- Do **not** read a session token from `ctx` inside this hook; use `user.id` instead.
- Fires on both `verifyAndroid` and `verifyIOS` endpoints.

The returned object is attached to the response under the `additionalData` key.

```ts
truecaller({
  clientId: process.env.TRUECALLER_CLIENT_ID!,

  onLoginSuccess: async ({ user, isNewUser, platform }) => {
    const profile = await db.profile.findUnique({ where: { userId: user.id } });
    return { profile };
  },
})
```

**Login response shape:**
```json
{
  "user": { "id": "...", "phoneNumber": "...", "..." },
  "session": { "token": "...", "expiresAt": "..." },
  "isNewUser": false,
  "additionalData": {
    "profile": { "..." }
  }
}
```

**Client access:**
```ts
const result = await authClient.truecaller.verifyAndroid({ authorizationCode });
const profile = result.data?.additionalData?.profile;
```

## Database schema

This plugin adds three fields to the `user` table. If you already use `better-auth-phone`, these fields are shared — no conflict.

| Field | Type | Notes |
|-------|------|-------|
| `phoneNumber` | `string` | unique, sortable |
| `countryCode` | `string` | dial code (e.g. `"+91"`) |
| `phoneNumberVerified` | `boolean` | set to `true` after Truecaller verification |

Run `better-auth generate` to produce the migration.

## Error codes

| Code | Description |
|------|-------------|
| `INVALID_PLATFORM` | Platform must be `ios` or `android` |
| `VERIFICATION_FAILED` | Truecaller verification failed |
| `UPSTREAM_TIMEOUT` | Truecaller API did not respond in time |
| `UPSTREAM_ERROR` | Truecaller API returned an error |
| `MISSING_ACCESS_TOKEN` | No access token in Truecaller OAuth response |
| `MISSING_PHONE_NUMBER` | Phone number missing in Truecaller response |
| `INVALID_PHONE_NUMBER` | Phone number in response is invalid |
| `INVALID_SIGNATURE` | iOS payload signature verification failed |
| `NONCE_MISMATCH` | iOS request nonce does not match payload |
| `NO_PUBLIC_KEYS` | Truecaller returned no public keys |
| `UNABLE_TO_PARSE_PAYLOAD` | iOS signed payload could not be parsed |

## License

MIT
