import globals from "globals";
import pluginJs from "@eslint/js";
import pluginReact from "eslint-plugin-react";
import pluginSecurity from "eslint-plugin-security";
/** @type {import('eslint').Linter.Config[]} */
export default [
{files: ["**/*.{js,mjs,cjs,jsx}"]},
{languageOptions: { globals: globals.browser }},
pluginJs.configs.recommended,
pluginReact.configs.flat.recommended,
{
plugins: {
security: pluginSecurity
},
rules: {
...pluginJs.configs.recommended.rules,
...pluginReact.configs.flat.recommended.rules,
"security/detect-eval-with-expression": "error",
}
}
];