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
   * Custom schema overrides.
   * Allows remapping DB column names via `{ fields: { phoneNumber: "phone" } }`.
   */
  schema?: InferOptionSchema<typeof schema>;
}

export interface RequiredTruecallerOptions
  extends Omit<TruecallerOptions, "signUpOnVerification"> {
  clientId: string;
  region: "eu" | "global";
  upstreamTimeoutMs: number;
  publicKeyCacheTTLMs: number;
  signUpOnVerification?: {
    getTempEmail: (phoneNumber: string) => string;
    getTempName?: (phoneNumber: string) => string;
  };
  // Resolved DB field name mappings (camelCase; schema config translates to actual column names)
  phoneNumber: string;
  countryCode: string;
  phoneNumberVerified: string;
}
