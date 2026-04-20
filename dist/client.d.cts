import * as better_auth from 'better-auth';
import { t as truecaller } from './index-DfAlvkVl.cjs';
export { R as RequiredTruecallerOptions, T as TRUECALLER_ERROR_CODES, a as TruecallerConfig, b as TruecallerNormalizedIdentity, c as TruecallerOptions, d as TruecallerParsedPayloadResult, e as TruecallerPlatform, f as TruecallerPublicKeyResponse, g as TruecallerSignatureVerificationResult, h as TruecallerVerificationResult, U as UserWithTruecaller } from './index-DfAlvkVl.cjs';
import 'better-call';
import 'zod/v4/core';
import 'zod';

/**
 * Client-side plugin for better-auth-truecaller.
 *
 * @example
 * ```ts
 * import { createAuthClient } from "better-auth/client";
 * import { truecallerClient } from "better-auth-truecaller/client";
 *
 * export const authClient = createAuthClient({
 *   plugins: [truecallerClient()],
 * });
 * ```
 */
declare const truecallerClient: () => {
    id: "betterAuthTruecaller";
    $InferServerPlugin: ReturnType<typeof truecaller>;
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
    atomListeners: {
        matcher(path: string): path is "/truecaller/verify-android" | "/truecaller/verify-ios";
        signal: "$sessionSignal";
    }[];
};

export { truecallerClient };
