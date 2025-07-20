import { defineConfig } from "eslint/config";
import js from "@eslint/js";
import pluginSecurityNode from "eslint-plugin-security-node";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import globals from "globals";

export default defineConfig([
  {
    files: ["**/*.{js,mjs,cjs,jsx}"],
    languageOptions: {
      globals: globals.browser, // This is fine if you're targeting browser environments
    },
    plugins: {
      "js": js,
      "security-node": pluginSecurityNode,
      "no-unsanitized": noUnsanitized,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...pluginSecurityNode.configs.recommended.rules,
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error",
    },
  },
]);
