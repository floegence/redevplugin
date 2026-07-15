import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/dist-test/**", "testdata/browser-harness/**/generated/**", "**/*.gen.ts"],
  },
  ...tseslint.configs.recommended,
  {
    files: [
      "packages/redevplugin-ui/src/**/*.ts",
      "packages/redevplugin-ui/test/**/*.ts",
      "examples/plugin-ui/**/*.ts",
      "examples/showcase/**/*.ts",
      "internal/scaffoldtemplate/**/*.ts",
      "testdata/browser-harness/**/*.ts",
    ],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
    },
  },
);
