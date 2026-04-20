import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

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
export const schema = {
  user: {
    fields: {
      phoneNumber: {
        type: "string",
        required: false,
        unique: true,
        sortable: true,
        returned: true,
      },
      countryCode: {
        type: "string",
        required: false,
        returned: true,
      },
      phoneNumberVerified: {
        type: "boolean",
        required: false,
        returned: true,
        input: false,
      },
    },
  },
} satisfies BetterAuthPluginDBSchema;
