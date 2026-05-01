import type { BetterAuthPlugin } from "better-auth";
import { mergeSchema } from "better-auth/db";
import { TRUECALLER_ERROR_CODES } from "./error-codes";
import { verifyTruecallerAndroid, verifyTruecallerIOS } from "./routes";
import { schema } from "./schema";
import type { RequiredTruecallerOptions, TruecallerOptions } from "./types";

export type { TruecallerOptions, UserWithTruecaller } from "./types";
export { TruecallerPlatform } from "./types";
export { TRUECALLER_ERROR_CODES };

/**
 * `truecaller` — Better Auth plugin for TrueCaller phone authentication.
 *
 * Supports:
 * - Android: OAuth authorization code flow
 * - iOS: Signed payload + signature verification
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { truecaller } from "better-auth-truecaller";
 *
 * export const auth = betterAuth({
 *   plugins: [
 *     truecaller({
 *       clientId: process.env.TRUECALLER_CLIENT_ID!,
 *       signUpOnVerification: {
 *         getTempEmail: (phone) => `${phone}@placeholder.invalid`,
 *       },
 *     }),
 *   ],
 * });
 * ```
 */
export const truecaller = (options: TruecallerOptions) => {
  if (!options.clientId) {
    throw new Error(
      "better-auth-truecaller: clientId is required. Please provide options.clientId",
    );
  }

  const region = options.region || "global";

  const oauthBaseUrlDefault =
    region === "eu"
      ? "https://oauth-account.truecaller.com"
      : "https://oauth-account-noneu.truecaller.com";

  const verificationBaseUrlDefault =
    region === "eu"
      ? "https://sdk-otp-verification.truecaller.com"
      : "https://sdk-otp-verification-noneu.truecaller.com";

  const publicKeyUrlDefault = "https://api4.truecaller.com/v1/key";

  const opts: RequiredTruecallerOptions = {
    region,
    upstreamTimeoutMs: options.upstreamTimeoutMs ?? 15000,
    publicKeyCacheTTLMs: options.publicKeyCacheTTLMs ?? 5 * 60 * 1000,
    ...options,
    populateFromTruecaller: {
      name: options.populateFromTruecaller?.name ?? true,
    },
    // Always use camelCase field names in plugin code;
    // schema config translates these to the actual DB column names.
    phoneNumber: "phoneNumber",
    countryCode: "countryCode",
    phoneNumberVerified: "phoneNumberVerified",
  };

  const config = {
    oauthBaseUrl: options.oauthBaseUrl ?? oauthBaseUrlDefault,
    verificationBaseUrl: options.verificationBaseUrl ?? verificationBaseUrlDefault,
    publicKeyUrl: options.publicKeyUrl ?? publicKeyUrlDefault,
    upstreamTimeoutMs: opts.upstreamTimeoutMs,
  };

  return {
    id: "better-auth-truecaller",

    endpoints: {
      verifyTruecallerAndroid: verifyTruecallerAndroid(opts, {
        oauthBaseUrl: config.oauthBaseUrl,
        upstreamTimeoutMs: config.upstreamTimeoutMs,
      }),
      verifyTruecallerIOS: verifyTruecallerIOS(opts, {
        publicKeyUrl: config.publicKeyUrl,
        upstreamTimeoutMs: config.upstreamTimeoutMs,
        publicKeyCacheTTLMs: opts.publicKeyCacheTTLMs,
      }),
    },

    schema: mergeSchema(schema, options.schema),

    rateLimit: [
      {
        pathMatcher(path: string) {
          return path.startsWith("/truecaller");
        },
        window: 60, // seconds — better-auth rate limiter multiplies by 1000 internally
        max: 10,
      },
    ],

    options: opts,
    $ERROR_CODES: TRUECALLER_ERROR_CODES,
  } satisfies BetterAuthPlugin;
};
