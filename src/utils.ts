import * as crypto from "crypto";
import axios from "axios";
import { APIError } from "better-call";
import { TRUECALLER_ERROR_CODES } from "./error-codes";
import type {
  TruecallerConfig,
  TruecallerNormalizedIdentity,
  TruecallerParsedPayloadResult,
  TruecallerPublicKeyResponse,
  TruecallerSignatureVerificationResult,
} from "./types";

// ── Constants ─────────────────────────────────────────────────────────────────

const TRUECALLER_SIGNATURE_ALGO_MAP: Record<string, string> = {
  SHA256withRSA: "RSA-SHA256",
  SHA384withRSA: "RSA-SHA384",
  SHA512withRSA: "RSA-SHA512",
};

/**
 * Comprehensive ISO 3166-1 alpha-2 → E.164 dial code mapping.
 * Covers all countries where TrueCaller operates.
 *
 * Previously this was a 3-entry map in the consuming app (IN/US/AE).
 * Inlined here so the plugin is self-contained and works for any country.
 */
const ISO_TO_DIAL_CODE: Record<string, string> = {
  AF: "93", AL: "355", DZ: "213", AS: "1684", AD: "376",
  AO: "244", AI: "1264", AQ: "672", AG: "1268", AR: "54",
  AM: "374", AW: "297", AU: "61", AT: "43", AZ: "994",
  BS: "1242", BH: "973", BD: "880", BB: "1246", BY: "375",
  BE: "32", BZ: "501", BJ: "229", BM: "1441", BT: "975",
  BO: "591", BA: "387", BW: "267", BR: "55", IO: "246",
  VG: "1284", BN: "673", BG: "359", BF: "226", BI: "257",
  KH: "855", CM: "237", CA: "1", CV: "238", KY: "1345",
  CF: "236", TD: "235", CL: "56", CN: "86", CX: "61",
  CC: "61", CO: "57", KM: "269", CG: "242", CD: "243",
  CK: "682", CR: "506", CI: "225", HR: "385", CU: "53",
  CW: "599", CY: "357", CZ: "420", DK: "45", DJ: "253",
  DM: "1767", DO: "1849", EC: "593", EG: "20", SV: "503",
  GQ: "240", ER: "291", EE: "372", ET: "251", FK: "500",
  FO: "298", FJ: "679", FI: "358", FR: "33", GF: "594",
  PF: "689", GA: "241", GM: "220", GE: "995", DE: "49",
  GH: "233", GI: "350", GR: "30", GL: "299", GD: "1473",
  GP: "590", GU: "1671", GT: "502", GG: "44", GN: "224",
  GW: "245", GY: "592", HT: "509", HN: "504", HK: "852",
  HU: "36", IS: "354", IN: "91", ID: "62", IR: "98",
  IQ: "964", IE: "353", IM: "44", IL: "972", IT: "39",
  JM: "1876", JP: "81", JE: "44", JO: "962", KZ: "7",
  KE: "254", KI: "686", KP: "850", KR: "82", KW: "965",
  KG: "996", LA: "856", LV: "371", LB: "961", LS: "266",
  LR: "231", LY: "218", LI: "423", LT: "370", LU: "352",
  MO: "853", MK: "389", MG: "261", MW: "265", MY: "60",
  MV: "960", ML: "223", MT: "356", MH: "692", MQ: "596",
  MR: "222", MU: "230", YT: "262", MX: "52", FM: "691",
  MD: "373", MC: "377", MN: "976", ME: "382", MS: "1664",
  MA: "212", MZ: "258", MM: "95", NA: "264", NR: "674",
  NP: "977", NL: "31", AN: "599", NC: "687", NZ: "64",
  NI: "505", NE: "227", NG: "234", NU: "683", NF: "672",
  MP: "1670", NO: "47", OM: "968", PK: "92", PW: "680",
  PS: "970", PA: "507", PG: "675", PY: "595", PE: "51",
  PH: "63", PN: "872", PL: "48", PT: "351", PR: "1939",
  QA: "974", RO: "40", RU: "7", RW: "250", RE: "262",
  BL: "590", SH: "290", KN: "1869", LC: "1758", MF: "590",
  PM: "508", VC: "1784", WS: "685", SM: "378", ST: "239",
  SA: "966", SN: "221", RS: "381", SC: "248", SL: "232",
  SG: "65", SX: "1721", SK: "421", SI: "386", SB: "677",
  SO: "252", ZA: "27", SS: "211", ES: "34", LK: "94",
  SD: "249", SR: "597", SJ: "47", SZ: "268", SE: "46",
  CH: "41", SY: "963", TW: "886", TJ: "992", TZ: "255",
  TH: "66", TL: "670", TG: "228", TK: "690", TO: "676",
  TT: "1868", TN: "216", TR: "90", TM: "993", TC: "1649",
  TV: "688", UG: "256", UA: "380", AE: "971", GB: "44",
  US: "1", UY: "598", UZ: "998", VU: "678", VE: "58",
  VN: "84", VI: "1340", WF: "681", YE: "967", ZM: "260",
  ZW: "263",
};

// ── Public key cache ──────────────────────────────────────────────────────────

/**
 * Fetch TrueCaller public keys with in-memory caching.
 * The cache object is owned by the caller (routes.ts) so it survives across
 * requests without being global state in this module.
 */
export async function getTruecallerPublicKeys(
  config: Pick<TruecallerConfig, "publicKeyUrl" | "upstreamTimeoutMs">,
  cache: { keys: string[]; fetchedAt: number } | null,
  cacheTTL: number,
): Promise<{ keys: string[]; cache: { keys: string[]; fetchedAt: number } }> {
  const now = Date.now();

  if (cache && now - cache.fetchedAt < cacheTTL) {
    return { keys: cache.keys, cache };
  }

  try {
    const response = await axios.get<TruecallerPublicKeyResponse[]>(
      config.publicKeyUrl,
      { timeout: config.upstreamTimeoutMs },
    );

    const keyEntries = (Array.isArray(response.data) ? response.data : []).filter(
      (entry): entry is TruecallerPublicKeyResponse => Boolean(entry?.key),
    );

    const keys = keyEntries
      .filter((entry) => !entry.keyType || entry.keyType.toUpperCase() === "RSA")
      .map((entry) => entry.key);

    if (!keys.length) {
      throw new APIError("BAD_GATEWAY", {
        message: TRUECALLER_ERROR_CODES.NO_PUBLIC_KEYS.message,
      });
    }

    const newCache = { keys, fetchedAt: now };
    return { keys, cache: newCache };
  } catch (error) {
    throw mapTruecallerAxiosError(error, {
      treatClientErrorsAsVerificationFailure: false,
    });
  }
}

// ── Signature verification ────────────────────────────────────────────────────

/**
 * Verify a TrueCaller iOS signed payload against fetched public keys.
 */
export function verifyTruecallerPayloadSignature(
  payload: string,
  signature: Uint8Array,
  signatureAlgorithm: string | undefined,
  publicKeys: string[],
): TruecallerSignatureVerificationResult {
  const algorithms = getTruecallerVerificationAlgorithms(signatureAlgorithm);

  for (let keyIndex = 0; keyIndex < publicKeys.length; keyIndex++) {
    const key = publicKeys[keyIndex];
    let publicKey: ReturnType<typeof crypto.createPublicKey>;

    try {
      publicKey = createTruecallerPublicKeyObject(key);
    } catch {
      continue;
    }

    for (const algorithm of algorithms) {
      try {
        const verifier = crypto.createVerify(algorithm);
        verifier.update(payload);
        verifier.end();
        const isValid = verifier.verify(publicKey, signature);
        if (isValid) {
          return { isValid, matchedAlgorithm: algorithm, matchedKeyIndex: keyIndex };
        }
      } catch {
        // try next combination
      }
    }
  }

  return { isValid: false };
}

function createTruecallerPublicKeyObject(keyValue: string) {
  const keyBuffer = Buffer.from(keyValue, "base64");
  try {
    return crypto.createPublicKey({ key: keyBuffer, format: "der", type: "spki" });
  } catch {
    const decodedKey = keyBuffer.toString("utf-8");
    if (decodedKey.includes("BEGIN PUBLIC KEY")) return crypto.createPublicKey(decodedKey);
    if (keyValue.includes("BEGIN PUBLIC KEY")) return crypto.createPublicKey(keyValue);
    throw new Error("Cannot create public key from provided value");
  }
}

function getTruecallerVerificationAlgorithms(signatureAlgorithm?: string): string[] {
  if (!signatureAlgorithm) return ["RSA-SHA512", "RSA-SHA256"];
  const mapped = TRUECALLER_SIGNATURE_ALGO_MAP[signatureAlgorithm] ?? signatureAlgorithm;
  return Array.from(new Set([mapped, "RSA-SHA512", "RSA-SHA256"]));
}

// ── Payload parsing ───────────────────────────────────────────────────────────

export function parseTruecallerSignedPayload(payload: string): TruecallerParsedPayloadResult {
  try {
    return { data: JSON.parse(payload), parseMode: "raw_json" };
  } catch {
    // fall through to base64
  }
  try {
    const decoded = Buffer.from(payload, "base64").toString("utf-8");
    return { data: JSON.parse(decoded), parseMode: "base64_json" };
  } catch {
    throw new APIError("UNAUTHORIZED", {
      message: TRUECALLER_ERROR_CODES.UNABLE_TO_PARSE_PAYLOAD.message,
    });
  }
}

// ── Identity normalization ────────────────────────────────────────────────────

/**
 * Normalize identity from TrueCaller API response (Android or iOS).
 *
 * Handles the various phone/countryCode field naming conventions across
 * TrueCaller SDK versions and platforms.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function normalizeTruecallerIdentity(data: Record<string, any>): TruecallerNormalizedIdentity {
  const phoneValue = getTruthyString(
    data.phoneNumber, data.phone_number, data.phone,
    data.msisdn, data.mobile, data.mobileNumber,
  );

  if (!phoneValue) {
    throw new APIError("UNAUTHORIZED", {
      message: TRUECALLER_ERROR_CODES.MISSING_PHONE_NUMBER.message,
    });
  }

  // Android returns phone_number_country_code as ISO alpha-2 (e.g. "IN")
  const countryCodeValue = data.phone_number_country_code;

  const { countryCode, phoneNumber } = normalizeTruecallerPhone(phoneValue, countryCodeValue);

  return {
    countryCode,
    phoneNumber,
    name: getTruecallerDisplayName(data),
    image: data.picture,
  };
}

/**
 * Resolve countryCode (dial code) and local phoneNumber from TrueCaller data.
 *
 * TrueCaller may return:
 *   - iOS:     countryCode as digit string (e.g. "91"),  phone includes prefix
 *   - Android: phone_number_country_code as ISO code (e.g. "IN"), phone includes prefix
 *   - Either:  no country code at all — fallback heuristic used
 */
function normalizeTruecallerPhone(
  phoneValue: string,
  countryCodeValue?: string,
): { countryCode: string; phoneNumber: string } {
  if (!phoneValue) {
    throw new APIError("UNAUTHORIZED", {
      message: TRUECALLER_ERROR_CODES.INVALID_PHONE_NUMBER.message,
    });
  }

  let dialCode: string | undefined;

  if (countryCodeValue && /^[A-Z]{2}$/i.test(countryCodeValue)) {
    // ISO alpha-2 → dial code
    dialCode = convertISOToDialCode(countryCodeValue);
  } else if (countryCodeValue && /^\d+$/.test(countryCodeValue)) {
    // Already a numeric dial code
    dialCode = countryCodeValue;
  }

  if (dialCode) {
    return {
      countryCode: dialCode,
      phoneNumber: stripDialCode(phoneValue, dialCode),
    };
  }

  // Heuristic fallback: assume 10-digit local number, everything before is country code
  if (phoneValue.length > 10) {
    return {
      countryCode: phoneValue.slice(0, phoneValue.length - 10),
      phoneNumber: phoneValue.slice(-10),
    };
  }

  return { countryCode: "", phoneNumber: phoneValue };
}

/**
 * Convert an ISO 3166-1 alpha-2 country code to its E.164 dial code.
 * Returns `undefined` if the code is not in the mapping.
 */
export function convertISOToDialCode(isoCode: string): string | undefined {
  return ISO_TO_DIAL_CODE[isoCode.toUpperCase()];
}

/**
 * Remove a dial code prefix from a phone number string if present.
 * Example: stripDialCode("919876543210", "91") → "9876543210"
 */
export function stripDialCode(phoneNumber: string, dialCode: string): string {
  if (phoneNumber.startsWith(dialCode)) {
    return phoneNumber.slice(dialCode.length);
  }
  return phoneNumber;
}

// ── Display name ──────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getTruecallerDisplayName(data: Record<string, any>): string | undefined {
  const explicit = getTruthyString(data.name, data.fullName);
  if (explicit) return explicit;

  const first = getTruthyString(data.firstName, data.first_name, data.given_name, data.givenName);
  const last = getTruthyString(data.lastName, data.last_name, data.family_name, data.familyName);
  const derived = [first, last].filter(Boolean).join(" ").trim();
  return derived || undefined;
}

// ── Error mapping ─────────────────────────────────────────────────────────────

/**
 * Map an axios error (or unknown error) to a typed APIError.
 */
export function mapTruecallerAxiosError(
  error: unknown,
  options: { treatClientErrorsAsVerificationFailure: boolean },
): Error {
  if (axios.isAxiosError(error)) {
    const code = error.code?.toUpperCase();
    if (code === "ECONNABORTED" || code === "ETIMEDOUT") {
      return new APIError("GATEWAY_TIMEOUT", {
        message: TRUECALLER_ERROR_CODES.UPSTREAM_TIMEOUT.message,
      });
    }
    const status = error.response?.status;
    if (options.treatClientErrorsAsVerificationFailure && status && status >= 400 && status < 500) {
      return new APIError("UNAUTHORIZED", {
        message: TRUECALLER_ERROR_CODES.VERIFICATION_FAILED.message,
      });
    }
    return new APIError("BAD_GATEWAY", {
      message: TRUECALLER_ERROR_CODES.UPSTREAM_ERROR.message,
    });
  }
  return new APIError("INTERNAL_SERVER_ERROR", {
    message: TRUECALLER_ERROR_CODES.INTERNAL_ERROR.message,
  });
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

/**
 * Return the first truthy trimmed string from the arguments.
 */
export function getTruthyString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (trimmed) return trimmed;
    }
  }
  return undefined;
}
