import config from "@iobroker/eslint-config";

export default [
  ...config,
  {
    languageOptions: {
      globals: {
        require: "readonly",
        module: "readonly",
        __dirname: "readonly",
        process: "readonly",
        console: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        Buffer: "readonly",
      },
    },
    rules: {
      // Relax some rules for this pure JS project
      "jsdoc/require-jsdoc": "off",
      "@typescript-eslint/no-require-imports": "off",
    },
  },
  {
    ignores: ["node_modules/", "admin/i18n/", ".vscode/"],
  },
];
