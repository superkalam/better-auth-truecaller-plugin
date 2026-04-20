import type { BetterAuthClientPlugin } from "@better-auth/core";
import type { truecaller } from "./index";
import { TRUECALLER_ERROR_CODES } from "./error-codes";

export type * from "./types";
export { TRUECALLER_ERROR_CODES };

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
export const truecallerClient = () => {
  return {
    id: "betterAuthTruecaller",
    $InferServerPlugin: {} as ReturnType<typeof truecaller>,
    $ERROR_CODES: TRUECALLER_ERROR_CODES,
    atomListeners: [
      {
        matcher(path: string) {
          return (
            path === "/truecaller/verify-android" ||
            path === "/truecaller/verify-ios"
          );
        },
        signal: "$sessionSignal",
      },
    ],
  } satisfies BetterAuthClientPlugin;
};
