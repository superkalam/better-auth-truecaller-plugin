import * as better_auth from 'better-auth';
import { GenericEndpointContext, Awaitable, User, InferOptionSchema } from 'better-auth';
import * as better_call from 'better-call';
import * as zod_v4_core from 'zod/v4/core';
import * as zod from 'zod';

declare const TRUECALLER_ERROR_CODES: {
    INVALID_PLATFORM: better_auth.RawError<"INVALID_PLATFORM">;
    MISSING_REQUIRED_FIELDS: better_auth.RawError<"MISSING_REQUIRED_FIELDS">;
    VERIFICATION_FAILED: better_auth.RawError<"VERIFICATION_FAILED">;
    UPSTREAM_TIMEOUT: better_auth.RawError<"UPSTREAM_TIMEOUT">;
    UPSTREAM_ERROR: better_auth.RawError<"UPSTREAM_ERROR">;
    INTERNAL_ERROR: better_auth.RawError<"INTERNAL_ERROR">;
    MISSING_ACCESS_TOKEN: better_auth.RawError<"MISSING_ACCESS_TOKEN">;
    MISSING_PHONE_NUMBER: better_auth.RawError<"MISSING_PHONE_NUMBER">;
    INVALID_PHONE_NUMBER: better_auth.RawError<"INVALID_PHONE_NUMBER">;
    INVALID_SIGNATURE: better_auth.RawError<"INVALID_SIGNATURE">;
    NONCE_MISMATCH: better_auth.RawError<"NONCE_MISMATCH">;
    NO_PUBLIC_KEYS: better_auth.RawError<"NO_PUBLIC_KEYS">;
    UNABLE_TO_PARSE_PAYLOAD: better_auth.RawError<"UNABLE_TO_PARSE_PAYLOAD">;
};

/**
 * TrueCaller plugin database schema.
 *
 * This plugin does not introduce new tables. It reuses the phone number fields
 * on the user model. If you are also using better-auth-phone, these fields will
 * already exist and will be compatible — both plugins share the same field names.
 *
 * If you are using TrueCaller without better-auth-phone, these fields will be
 * added by this plugin's schema declaration.
 */
declare const schema: {
    user: {
        fields: {
            phoneNumber: {
                type: "string";
                required: false;
                unique: true;
                sortable: true;
                returned: true;
            };
            countryCode: {
                type: "string";
                required: false;
                returned: true;
            };
            phoneNumberVerified: {
                type: "boolean";
                required: false;
                returned: true;
                input: false;
            };
        };
    };
};

declare enum TruecallerPlatform {
    IOS = "ios",
    ANDROID = "android"
}
interface TruecallerNormalizedIdentity {
    countryCode: string;
    phoneNumber: string;
    name?: string;
    image?: string;
}
interface TruecallerVerificationResult {
    identity: TruecallerNormalizedIdentity;
}
interface TruecallerSignatureVerificationResult {
    isValid: boolean;
    matchedAlgorithm?: string;
    matchedKeyIndex?: number;
}
interface TruecallerParsedPayloadResult {
    data: Record<string, any>;
    parseMode: "raw_json" | "base64_json";
}
interface TruecallerPublicKeyResponse {
    keyType?: string;
    key: string;
}
interface TruecallerConfig {
    region: "eu" | "global";
    clientId: string;
    oauthBaseUrl: string;
    verificationBaseUrl: string;
    publicKeyUrl: string;
    upstreamTimeoutMs: number;
}
interface UserWithTruecaller extends User {
    phoneNumber: string | null;
    countryCode: string | null;
    phoneNumberVerified: boolean;
}
/**
 * TrueCaller plugin options
 */
interface TruecallerOptions {
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
    onVerificationSuccess?: (data: {
        platform: TruecallerPlatform;
        identity: TruecallerNormalizedIdentity;
    }, ctx: GenericEndpointContext) => Awaitable<void>;
    /**
     * Called after the user is found or created.
     */
    callbackAfterVerification?: (data: {
        user: UserWithTruecaller;
        isNewUser: boolean;
        platform: TruecallerPlatform;
    }, ctx: GenericEndpointContext) => Awaitable<void>;
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
    onLoginSuccess?: (data: {
        user: UserWithTruecaller;
        isNewUser: boolean;
        platform: TruecallerPlatform;
    }, ctx: GenericEndpointContext) => Awaitable<Record<string, unknown>>;
    /**
     * Custom schema overrides.
     * Allows remapping DB column names via `{ fields: { phoneNumber: "phone" } }`.
     */
    schema?: InferOptionSchema<typeof schema>;
}
interface RequiredTruecallerOptions extends Omit<TruecallerOptions, "signUpOnVerification" | "populateFromTruecaller"> {
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
    phoneNumber: string;
    countryCode: string;
    phoneNumberVerified: string;
}

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
declare const truecaller: (options: TruecallerOptions) => {
    id: "better-auth-truecaller";
    endpoints: {
        verifyTruecallerAndroid: better_call.StrictEndpoint<"/truecaller/verify-android", {
            method: "POST";
            body: zod.ZodObject<{
                authorizationCode: zod.ZodString;
                codeVerifier: zod.ZodOptional<zod.ZodString>;
            }, zod_v4_core.$strip>;
            metadata: {
                openapi: {
                    summary: string;
                    description: string;
                    responses: {
                        200: {
                            description: string;
                            content: {
                                "application/json": {
                                    schema: {
                                        type: "object";
                                        properties: {
                                            user: {
                                                $ref: string;
                                            };
                                            session: {
                                                $ref: string;
                                            };
                                        };
                                    };
                                };
                            };
                        };
                        401: {
                            description: string;
                        };
                    };
                };
            };
        }, {
            additionalData?: Record<string, unknown> | undefined;
            user: {
                id: string;
                email: string;
                emailVerified: boolean;
                name: string;
                image: string | null | undefined;
                phoneNumber: string | null;
                countryCode: string | null;
                phoneNumberVerified: boolean;
                createdAt: Date;
                updatedAt: Date;
            };
            session: {
                token: string;
                expiresAt: Date;
            };
            isNewUser: boolean;
        }>;
        verifyTruecallerIOS: better_call.StrictEndpoint<"/truecaller/verify-ios", {
            method: "POST";
            body: zod.ZodObject<{
                payload: zod.ZodString;
                signature: zod.ZodString;
                requestNonce: zod.ZodString;
                signatureAlgorithm: zod.ZodOptional<zod.ZodString>;
            }, zod_v4_core.$strip>;
            metadata: {
                openapi: {
                    summary: string;
                    description: string;
                    responses: {
                        200: {
                            description: string;
                            content: {
                                "application/json": {
                                    schema: {
                                        type: "object";
                                        properties: {
                                            user: {
                                                $ref: string;
                                            };
                                            session: {
                                                $ref: string;
                                            };
                                        };
                                    };
                                };
                            };
                        };
                        401: {
                            description: string;
                        };
                    };
                };
            };
        }, {
            additionalData?: Record<string, unknown> | undefined;
            user: {
                id: string;
                email: string;
                emailVerified: boolean;
                name: string;
                image: string | null | undefined;
                phoneNumber: string | null;
                countryCode: string | null;
                phoneNumberVerified: boolean;
                createdAt: Date;
                updatedAt: Date;
            };
            session: {
                token: string;
                expiresAt: Date;
            };
            isNewUser: boolean;
        }>;
    };
    schema: {
        user: {
            fields: {
                phoneNumber: {
                    type: "string";
                    required: false;
                    unique: true;
                    sortable: true;
                    returned: true;
                };
                countryCode: {
                    type: "string";
                    required: false;
                    returned: true;
                };
                phoneNumberVerified: {
                    type: "boolean";
                    required: false;
                    returned: true;
                    input: false;
                };
            };
        };
    };
    rateLimit: {
        pathMatcher(path: string): boolean;
        window: number;
        max: number;
    }[];
    options: RequiredTruecallerOptions;
    $ERROR_CODES: {
        INVALID_PLATFORM: better_auth.RawError<"INVALID_PLATFORM">;
        MISSING_REQUIRED_FIELDS: better_auth.RawError<"MISSING_REQUIRED_FIELDS">;
        VERIFICATION_FAILED: better_auth.RawError<"VERIFICATION_FAILED">;
        UPSTREAM_TIMEOUT: better_auth.RawError<"UPSTREAM_TIMEOUT">;
        UPSTREAM_ERROR: better_auth.RawError<"UPSTREAM_ERROR">;
        INTERNAL_ERROR: better_auth.RawError<"INTERNAL_ERROR">;
        MISSING_ACCESS_TOKEN: better_auth.RawError<"MISSING_ACCESS_TOKEN">;
        MISSING_PHONE_NUMBER: better_auth.RawError<"MISSING_PHONE_NUMBER">;
        INVALID_PHONE_NUMBER: better_auth.RawError<"INVALID_PHONE_NUMBER">;
        INVALID_SIGNATURE: better_auth.RawError<"INVALID_SIGNATURE">;
        NONCE_MISMATCH: better_auth.RawError<"NONCE_MISMATCH">;
        NO_PUBLIC_KEYS: better_auth.RawError<"NO_PUBLIC_KEYS">;
        UNABLE_TO_PARSE_PAYLOAD: better_auth.RawError<"UNABLE_TO_PARSE_PAYLOAD">;
    };
};

export { type RequiredTruecallerOptions as R, TRUECALLER_ERROR_CODES as T, type UserWithTruecaller as U, type TruecallerConfig as a, type TruecallerNormalizedIdentity as b, type TruecallerOptions as c, type TruecallerParsedPayloadResult as d, TruecallerPlatform as e, type TruecallerPublicKeyResponse as f, type TruecallerSignatureVerificationResult as g, type TruecallerVerificationResult as h, truecaller as t };
