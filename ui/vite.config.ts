import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'
import { bundledPackages } from './scripts/bundled.ts'

export default defineConfig({
  // bundledPackages writes the packages the bundle contains next to dist, for the image SBOM.
  plugins: [react(), tailwindcss(), bundledPackages()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  base: '/',
  build: {
    outDir: '../internal/web/ui/dist',
    emptyOutDir: false,
    sourcemap: false,
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8099',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    exclude: ['e2e/**', 'node_modules/**'],
  },
})
