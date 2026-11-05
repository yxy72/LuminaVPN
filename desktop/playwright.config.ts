import { defineConfig } from '@playwright/test'
export default defineConfig({
  testDir: 'tests', testMatch: '**/*.electron.ts', workers: 1,
  outputDir: '../.local/desktop-test-results', reporter: 'list', timeout: 30000
})
