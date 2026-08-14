import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    env: {
      NEXTAUTH_SECRET: "test_secret_for_vitest_unit_runs",
    },
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      reportsDirectory: "./coverage",
      // J02 — `all: true` so coverage counts untested source files and can
      // fail; thresholds set at the measured floor (ratchet may only rise).
      all: true,
      thresholds: {
        lines: 50,
        functions: 50,
        branches: 80,
        statements: 50,
      },
      exclude: [
        "src/**/*.spec.ts",
        "src/**/tests/**",
        "src/**/dto/**",
        "src/main.ts",
        "src/tracing.ts",
        "src/**/*.module.ts",
      ],
    },
  },
});
