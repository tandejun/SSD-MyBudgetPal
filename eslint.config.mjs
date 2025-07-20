import js from "@eslint/js";
import pluginSecurityNode from "eslint-plugin-security-node";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import globals from "globals";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    files: ["**/*.{js,mjs,cjs,jsx}"],
    languageOptions: {
      globals: globals.browser
    },
    plugins: {
      js,
      "security-node": pluginSecurityNode,
      "no-unsanitized": noUnsanitized
    },
    rules: {
      ...js.configs.recommended.rules,
      ...pluginSecurityNode.configs.recommended.rules,
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error"
    }
  }
]);
