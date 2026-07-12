import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/dist-test/**", "demo/browser/generated/**", "**/*.gen.ts"],
  },
  ...tseslint.configs.recommended,
  {
    files: ["packages/redevplugin-ui/src/**/*.ts", "packages/redevplugin-ui/test/**/*.ts", "demo/browser/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
    },
  },
);
