import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-call";
import { BASE_ERROR_CODES } from "@better-auth/core/error";
import { setSessionCookie } from "better-auth/cookies";
import * as z from "zod";
import axios from "axios";
import { TRUECALLER_ERROR_CODES } from "./error-codes";
import type {
  RequiredTruecallerOptions,
  TruecallerNormalizedIdentity,
  TruecallerPlatform,
  TruecallerVerificationResult,
  UserWithTruecaller,
} from "./types";
import {
  getTruecallerPublicKeys,
  mapTruecallerAxiosError,
  normalizeTruecallerIdentity,
  parseTruecallerSignedPayload,
  getTruthyString,
  verifyTruecallerPayloadSignature,
} from "./utils";

// In-memory public key cache — scoped to the module, shared across requests
let publicKeyCache: { keys: string[]; fetchedAt: number } | null = null;

// ── Body schemas ──────────────────────────────────────────────────────────────

const verifyAndroidBodySchema = z.object({
  authorizationCode: z.string().meta({
    description: "Authorization code from TrueCaller Android SDK",
  }),
  codeVerifier: z.string().optional().meta({
    description: "PKCE code verifier (optional)",
  }),
});

const verifyIOSBodySchema = z.object({
  payload: z.string().meta({
    description: "Signed payload from TrueCaller iOS SDK",
  }),
  signature: z.string().meta({
    description: "Signature of the payload",
  }),
  requestNonce: z.string().meta({
    description: "Request nonce for replay protection",
  }),
  signatureAlgorithm: z.string().optional().meta({
    description: "Signature algorithm used (optional)",
  }),
});

// ── Endpoint: verifyTruecallerAndroid ─────────────────────────────────────────

/**
 * POST `/truecaller/verify-android`
 *
 * server: `auth.api.verifyTruecallerAndroid`
 * client: `authClient.truecaller.verifyAndroid`
 */
export const verifyTruecallerAndroid = (
  opts: RequiredTruecallerOptions,
  config: {
    oauthBaseUrl: string;
    upstreamTimeoutMs: number;
  },
) =>
  createAuthEndpoint(
    "/truecaller/verify-android",
    {
      method: "POST",
      body: verifyAndroidBodySchema,
      metadata: {
        openapi: {
          summary: "Verify TrueCaller Android authentication",
          description:
            "Exchange an authorization code from the TrueCaller Android SDK for a Better Auth session.",
          responses: {
            200: {
              description: "Success",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      user: { $ref: "#/components/schemas/User" },
                      session: { $ref: "#/components/schemas/Session" },
                    },
                  },
                },
              },
            },
            401: { description: "Verification failed" },
          },
        },
      },
    },
    async (ctx) => {
      const { authorizationCode, codeVerifier } = ctx.body;

      let identity: TruecallerNormalizedIdentity;
      try {
        const result = await verifyTruecallerAndroidOAuth(
          { authorizationCode, codeVerifier, clientId: opts.clientId },
          config,
        );
        identity = result.identity;
      } catch (error) {
        ctx.context.logger.error("TrueCaller Android verification failed", error);
        throw error;
      }

      if (opts.onVerificationSuccess) {
        await opts.onVerificationSuccess(
          { platform: "android" as TruecallerPlatform, identity },
          ctx,
        );
      }

      const { user, isNewUser } = await findOrCreateUserFromTruecaller(identity, opts, ctx);

      if (opts.callbackAfterVerification) {
        await ctx.context.runInBackgroundOrAwait(
          opts.callbackAfterVerification(
            { user, isNewUser, platform: "android" as TruecallerPlatform },
            ctx,
          ),
        );
      }

      const session = await ctx.context.internalAdapter.createSession(user.id);
      if (!session) {
        throw new APIError("INTERNAL_SERVER_ERROR", { message: BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION.message });
      }

      await setSessionCookie(ctx, { session, user });

      return ctx.json({
        user: serializeUser(user),
        session: { token: session.token, expiresAt: session.expiresAt },
      });
    },
  );

// ── Endpoint: verifyTruecallerIOS ─────────────────────────────────────────────

/**
 * POST `/truecaller/verify-ios`
 *
 * server: `auth.api.verifyTruecallerIOS`
 * client: `authClient.truecaller.verifyIOS`
 */
export const verifyTruecallerIOS = (
  opts: RequiredTruecallerOptions,
  config: {
    publicKeyUrl: string;
    upstreamTimeoutMs: number;
    publicKeyCacheTTLMs: number;
  },
) =>
  createAuthEndpoint(
    "/truecaller/verify-ios",
    {
      method: "POST",
      body: verifyIOSBodySchema,
      metadata: {
        openapi: {
          summary: "Verify TrueCaller iOS authentication",
          description:
            "Verify a signed payload from the TrueCaller iOS SDK and create a Better Auth session.",
          responses: {
            200: {
              description: "Success",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      user: { $ref: "#/components/schemas/User" },
                      session: { $ref: "#/components/schemas/Session" },
                    },
                  },
                },
              },
            },
            401: { description: "Verification failed" },
          },
        },
      },
    },
    async (ctx) => {
      const { payload, signature, requestNonce, signatureAlgorithm } = ctx.body;

      let identity: TruecallerNormalizedIdentity;
      try {
        const result = await verifyTruecallerIOSSignedPayload(
          { payload, signature, requestNonce, signatureAlgorithm },
          config,
        );
        identity = result.identity;
      } catch (error) {
        ctx.context.logger.error("TrueCaller iOS verification failed", error);
        throw error;
      }

      if (opts.onVerificationSuccess) {
        await opts.onVerificationSuccess(
          { platform: "ios" as TruecallerPlatform, identity },
          ctx,
        );
      }

      const { user, isNewUser } = await findOrCreateUserFromTruecaller(identity, opts, ctx);

      if (opts.callbackAfterVerification) {
        await ctx.context.runInBackgroundOrAwait(
          opts.callbackAfterVerification(
            { user, isNewUser, platform: "ios" as TruecallerPlatform },
            ctx,
          ),
        );
      }

      const session = await ctx.context.internalAdapter.createSession(user.id);
      if (!session) {
        throw new APIError("INTERNAL_SERVER_ERROR", { message: BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION.message });
      }

      await setSessionCookie(ctx, { session, user });

      return ctx.json({
        user: serializeUser(user),
        session: { token: session.token, expiresAt: session.expiresAt },
      });
    },
  );

// ── Internal: Android OAuth flow ──────────────────────────────────────────────

async function verifyTruecallerAndroidOAuth(
  params: { authorizationCode: string; codeVerifier?: string; clientId: string },
  config: { oauthBaseUrl: string; upstreamTimeoutMs: number },
): Promise<TruecallerVerificationResult> {
  const { authorizationCode, codeVerifier, clientId } = params;

  let accessToken: string;
  try {
    const tokenPayload = new URLSearchParams({
      grant_type: "authorization_code",
      code: authorizationCode,
      client_id: clientId,
    });
    if (codeVerifier?.trim()) {
      tokenPayload.set("code_verifier", codeVerifier.trim());
    }

    const tokenResponse = await axios.post(
      `${config.oauthBaseUrl}/v1/token`,
      tokenPayload.toString(),
      {
        timeout: config.upstreamTimeoutMs,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      },
    );

    accessToken =
      tokenResponse?.data?.access_token ?? tokenResponse?.data?.accessToken;

    if (!accessToken) {
      throw new APIError("BAD_GATEWAY", {
        message: TRUECALLER_ERROR_CODES.MISSING_ACCESS_TOKEN.message,
      });
    }
  } catch (error) {
    throw mapTruecallerAxiosError(error, { treatClientErrorsAsVerificationFailure: true });
  }

  try {
    const userInfoResponse = await axios.get(`${config.oauthBaseUrl}/v1/userinfo`, {
      timeout: config.upstreamTimeoutMs,
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const identity = normalizeTruecallerIdentity(userInfoResponse.data);
    return { identity };
  } catch (error) {
    throw mapTruecallerAxiosError(error, { treatClientErrorsAsVerificationFailure: true });
  }
}

// ── Internal: iOS signed payload flow ────────────────────────────────────────

async function verifyTruecallerIOSSignedPayload(
  params: { payload: string; signature: string; requestNonce: string; signatureAlgorithm?: string },
  config: { publicKeyUrl: string; upstreamTimeoutMs: number; publicKeyCacheTTLMs: number },
): Promise<TruecallerVerificationResult> {
  const { payload, signature, requestNonce, signatureAlgorithm } = params;

  let publicKeys: string[];
  try {
    const result = await getTruecallerPublicKeys(
      { publicKeyUrl: config.publicKeyUrl, upstreamTimeoutMs: config.upstreamTimeoutMs },
      publicKeyCache,
      config.publicKeyCacheTTLMs,
    );
    publicKeys = result.keys;
    publicKeyCache = result.cache;
  } catch (error) {
    throw mapTruecallerAxiosError(error, { treatClientErrorsAsVerificationFailure: false });
  }

  const signatureBytes = Uint8Array.from(Buffer.from(signature, "base64"));
  const signatureResult = verifyTruecallerPayloadSignature(
    payload,
    signatureBytes,
    signatureAlgorithm,
    publicKeys,
  );

  if (!signatureResult.isValid) {
    throw new APIError("UNAUTHORIZED", {
      message: TRUECALLER_ERROR_CODES.INVALID_SIGNATURE.message,
    });
  }

  const parsedPayloadResult = parseTruecallerSignedPayload(payload);
  const parsedPayload = parsedPayloadResult.data;

  const nonceInPayload = getTruthyString(
    parsedPayload.requestNonce,
    parsedPayload.request_nonce,
    parsedPayload.nonce,
  );
  if (!nonceInPayload || nonceInPayload !== requestNonce) {
    throw new APIError("UNAUTHORIZED", {
      message: TRUECALLER_ERROR_CODES.NONCE_MISMATCH.message,
    });
  }

  const identity = normalizeTruecallerIdentity(parsedPayload);
  return { identity };
}

// ── Internal: user lookup / creation ─────────────────────────────────────────

async function findOrCreateUserFromTruecaller(
  identity: TruecallerNormalizedIdentity,
  opts: RequiredTruecallerOptions,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ctx: any,
): Promise<{ user: UserWithTruecaller; isNewUser: boolean }> {
  const { countryCode, phoneNumber, name } = identity;

  const existingUser = (await ctx.context.adapter.findOne({
    model: "user",
    where: [
      { field: opts.phoneNumber, value: phoneNumber },
      { field: opts.countryCode, value: countryCode },
    ],
  })) as UserWithTruecaller | null;

  if (existingUser) {
    if (!existingUser.phoneNumberVerified) {
      const updatedUser = (await ctx.context.internalAdapter.updateUser(
        existingUser.id,
        { [opts.phoneNumberVerified]: true },
      )) as UserWithTruecaller;
      return { user: updatedUser, isNewUser: false };
    }
    return { user: existingUser, isNewUser: false };
  }

  if (!opts.signUpOnVerification) {
    throw new APIError("UNAUTHORIZED", {
      message: "User not found and auto-signup is disabled",
    });
  }

  const fullPhone = `${countryCode}${phoneNumber}`;
  const tempEmail = opts.signUpOnVerification.getTempEmail(fullPhone);
  const userName =
    name ||
    (opts.signUpOnVerification.getTempName
      ? opts.signUpOnVerification.getTempName(fullPhone)
      : fullPhone);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const userPayload: Record<string, any> = {
    email: tempEmail,
    name: userName,
    [opts.phoneNumber]: phoneNumber,
    [opts.countryCode]: countryCode,
    [opts.phoneNumberVerified]: true,
  };

  if (identity.image) {
    userPayload.image = identity.image;
  }

  const newUser = (await ctx.context.internalAdapter.createUser(
    userPayload,
  )) as UserWithTruecaller;

  if (!newUser) {
    throw new APIError("INTERNAL_SERVER_ERROR", { message: BASE_ERROR_CODES.FAILED_TO_CREATE_USER.message });
  }

  return { user: newUser, isNewUser: true };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function serializeUser(user: UserWithTruecaller) {
  return {
    id: user.id,
    email: user.email,
    emailVerified: user.emailVerified,
    name: user.name,
    image: user.image,
    phoneNumber: user.phoneNumber,
    countryCode: user.countryCode,
    phoneNumberVerified: user.phoneNumberVerified,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}
