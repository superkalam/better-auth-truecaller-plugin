import type { Awaitable, GenericEndpointContext, InferOptionSchema, User } from "better-auth";
import type { schema } from "./schema";

export enum TruecallerPlatform {
  IOS = "ios",
  ANDROID = "android",
}

export interface TruecallerNormalizedIdentity {
  countryCode: string;
  phoneNumber: string;
  name?: string;
  image?: string;
}

export interface TruecallerVerificationResult {
  identity: TruecallerNormalizedIdentity;
}

export interface TruecallerSignatureVerificationResult {
  isValid: boolean;
  matchedAlgorithm?: string;
  matchedKeyIndex?: number;
}

export interface TruecallerParsedPayloadResult {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: Record<string, any>;
  parseMode: "raw_json" | "base64_json";
}

export interface TruecallerPublicKeyResponse {
  keyType?: string;
  key: string;
}

export interface TruecallerConfig {
  region: "eu" | "global";
  clientId: string;
  oauthBaseUrl: string;
  verificationBaseUrl: string;
  publicKeyUrl: string;
  upstreamTimeoutMs: number;
}

export interface UserWithTruecaller extends User {
  phoneNumber: string | null;
  countryCode: string | null;
  phoneNumberVerified: boolean;
}

/**
 * TrueCaller plugin options
 */
export interface TruecallerOptions {
  /**
   * TrueCaller region.
   * @default 'global'
   */
  region?: "eu" | "global";

  /**
   * TrueCaller client ID. **Required.**
   */
  clientId: string;

  /**
   * Custom OAuth base URL.
   * Defaults to the region-appropriate TrueCaller endpoint.
   */
  oauthBaseUrl?: string;

  /**
   * Custom verification base URL.
   * Defaults to the region-appropriate TrueCaller endpoint.
   */
  verificationBaseUrl?: string;

  /**
   * Custom public key URL.
   * @default 'https://api4.truecaller.com/v1/key'
   */
  publicKeyUrl?: string;

  /**
   * Upstream HTTP request timeout in milliseconds.
   * @default 15000
   */
  upstreamTimeoutMs?: number;

  /**
   * In-memory public key cache TTL in milliseconds.
   * @default 300000 (5 minutes)
   */
  publicKeyCacheTTLMs?: number;

  /**
   * Controls which fields from TrueCaller's identity response are written to the user record.
   *
   * Fields default to `true` (populated). Set a field to `false` to skip it — the plugin
   * will fall back to the `signUpOnVerification` helper (e.g. `getTempName`) or a safe default.
   *
   * @example
   * ```ts
   * // Don't use the TrueCaller-provided name; always call getTempName instead.
   * populateFromTruecaller: { name: false }
   * ```
   */
  populateFromTruecaller?: {
    /**
     * Whether to use the name returned by TrueCaller.
     * When `false`, `signUpOnVerification.getTempName` (or the full phone number) is used instead.
     * @default true
     */
    name?: boolean;
  };

  /**
   * Auto-create a user account after successful TrueCaller verification.
   *
   * A temporary email is required by Better Auth's user model. You can update
   * the email later via a separate flow.
   */
  signUpOnVerification?: {
    /**
     * Return a temporary email for the new user.
     * The full phone number (countryCode + localNumber, e.g. "919876543210") is passed.
     */
    getTempEmail: (phoneNumber: string) => string;
    /**
     * Return a temporary display name for the new user.
     * Falls back to the TrueCaller-provided name, then the full phone number.
     */
    getTempName?: (phoneNumber: string) => string;
  };

  /**
   * Called after TrueCaller verifies the identity, before user lookup/creation.
   */
  onVerificationSuccess?: (
    data: {
      platform: TruecallerPlatform;
      identity: TruecallerNormalizedIdentity;
    },
    ctx: GenericEndpointContext,
  ) => Awaitable<void>;

  /**
   * Called after the user is found or created.
   */
  callbackAfterVerification?: (
    data: {
      user: UserWithTruecaller;
      isNewUser: boolean;
      platform: TruecallerPlatform;
    },
    ctx: GenericEndpointContext,
  ) => Awaitable<void>;

  /**
   * Called after the user is found or created, **before the session is created**.
   *
   * Executes in parallel with `createSession` — both run at the same time so there
   * is no added latency compared to running sequentially. Because it fires before
   * the session exists, do NOT read `ctx` for a session token here; use `user.id`
   * to query any additional data you need.
   *
   * The returned object is attached to the login response under the `additionalData` key,
   * allowing the client to receive any extra data in the same round-trip as the login itself.
   *
   * Fires on both `verifyAndroid` and `verifyIOS` endpoints.
   *
   * @example
   * ```ts
   * onLoginSuccess: async ({ user, isNewUser, platform }) => {
   *   const profile = await db.profile.findUnique({ where: { userId: user.id } });
   *   return { profile };
   * }
   * // Login response: { user, session, isNewUser, additionalData: { profile: { ... } } }
   * ```
   */
  onLoginSuccess?: (
    data: { user: UserWithTruecaller; isNewUser: boolean; platform: TruecallerPlatform },
    ctx: GenericEndpointContext,
  ) => Awaitable<Record<string, unknown>>;

  /**
   * Custom schema overrides.
   * Allows remapping DB column names via `{ fields: { phoneNumber: "phone" } }`.
   */
  schema?: InferOptionSchema<typeof schema>;
}

export interface RequiredTruecallerOptions
  extends Omit<TruecallerOptions, "signUpOnVerification" | "populateFromTruecaller"> {
  clientId: string;
  region: "eu" | "global";
  upstreamTimeoutMs: number;
  publicKeyCacheTTLMs: number;
  signUpOnVerification?: {
    getTempEmail: (phoneNumber: string) => string;
    getTempName?: (phoneNumber: string) => string;
  };
  populateFromTruecaller: {
    name: boolean;
  };
  // Resolved DB field name mappings (camelCase; schema config translates to actual column names)
  phoneNumber: string;
  countryCode: string;
  phoneNumberVerified: string;
}
