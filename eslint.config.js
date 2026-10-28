"use strict";

/**
 * Minimal ESLint flat config (ESLint 9). Deliberately self-contained — no
 * @eslint/js or plugin dependencies — so `npm ci` stays small and offline-friendly.
 */
module.exports = [
  {
    ignores: ["node_modules/**", "public/**", "data/**", "coverage/**"],
  },
  {
    files: ["src/**/*.js", "test/**/*.js", "scripts/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        console: "readonly",
        process: "readonly",
        require: "readonly",
        module: "readonly",
        exports: "writable",
        __dirname: "readonly",
        __filename: "readonly",
        Buffer: "readonly",
        URL: "readonly",
        fetch: "readonly",
        setTimeout: "readonly",
        setInterval: "readonly",
        clearTimeout: "readonly",
        clearInterval: "readonly",
        globalThis: "readonly",
      },
    },
    rules: {
      "no-undef": "error",
      "no-var": "error",
      "prefer-const": "warn",
      eqeqeq: ["warn", "smart"],
      "no-unused-vars": ["warn", {
        argsIgnorePattern: "^_",
        varsIgnorePattern: "^_",
        caughtErrors: "none",
      }],
      "no-implicit-globals": "off",
      "no-console": "off",
    },
  },
];