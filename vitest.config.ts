import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    env: {
      NEXTAUTH_SECRET: 'test_secret_for_vitest_unit_runs',
    },
  },
});
