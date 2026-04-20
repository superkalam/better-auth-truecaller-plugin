import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

export const TRUECALLER_ERROR_CODES = defineErrorCodes({
  INVALID_PLATFORM: "Invalid platform. Must be 'ios' or 'android'",
  MISSING_REQUIRED_FIELDS: "Missing required TrueCaller fields",
  VERIFICATION_FAILED: "TrueCaller verification failed",
  UPSTREAM_TIMEOUT: "TrueCaller upstream timeout",
  UPSTREAM_ERROR: "TrueCaller upstream error",
  INTERNAL_ERROR: "Internal error during TrueCaller verification",
  MISSING_ACCESS_TOKEN: "Missing access token from TrueCaller OAuth response",
  MISSING_PHONE_NUMBER: "Phone number missing in TrueCaller response",
  INVALID_PHONE_NUMBER: "Invalid phone number in TrueCaller response",
  INVALID_SIGNATURE: "Signed TrueCaller payload verification failed",
  NONCE_MISMATCH: "TrueCaller request nonce mismatch",
  NO_PUBLIC_KEYS: "No public keys returned from TrueCaller",
  UNABLE_TO_PARSE_PAYLOAD: "Unable to parse signed TrueCaller payload",
});

export type TruecallerErrorCode = keyof typeof TRUECALLER_ERROR_CODES;
