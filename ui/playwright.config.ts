import { defineConfig } from '@playwright/test'

// The end-to-end suite runs against hack/uiserve over the Small fixture: the real Go handler, guards
// and live-update hub, serving the freshly built UI. One worker, because there is one server, the
// live spec changes its store and the performance spec must not share the CPU.
export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]] : 'list',
  use: {
    baseURL: 'http://127.0.0.1:8099',
    browserName: 'chromium',
    channel: process.env.FFS_PW_CHANNEL || undefined,
    viewport: { width: 1440, height: 900 },
    trace: 'retain-on-failure',
  },
  webServer: {
    // npm run build, not make ui: make ui runs npm ci, which would delete node_modules under the
    // running test runner. go run embeds the fresh dist.
    command: 'npm run build && cd .. && CGO_ENABLED=0 GOFLAGS=-p=4 go run ./hack/uiserve',
    url: 'http://127.0.0.1:8099/api/v1/feeds',
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
    stdout: 'pipe',
    gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
  },
})
