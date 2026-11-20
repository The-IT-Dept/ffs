// Tests of the bundled-packages list (bundled.ts), run with node --test (npm run test:scripts): they
// build the UI in memory, which writes nothing.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { type BundledPackage, bundledPackageList, cssRefs, packageDirOf } from './bundled.ts'

function versionOf(name: string): string {
  const file = fileURLToPath(new URL(`../node_modules/${name}/package.json`, import.meta.url))
  return (JSON.parse(readFileSync(file, 'utf8')) as { version: string }).version
}

test('the bundle lists what it contains and only that', async () => {
  const list: BundledPackage[] = await bundledPackageList()
  const byName = new Map(list.map((p) => [p.name, p]))

  // A bundled runtime dependency, with name, version and licence from its own package.json.
  assert.deepEqual(byName.get('react'), { path: 'node_modules/react', name: 'react', version: versionOf('react'), license: 'MIT' })
  // Bundled CSS (Tailwind inlines it, outside the module graph) and the bundler's helpers.
  for (const name of ['tailwindcss', 'tw-animate-css', 'vite', 'rolldown']) assert.ok(byName.has(name), `${name} is bundled`)
  // Dev-only packages that are never bundled, and a production dependency the bundle tree-shakes away.
  for (const name of ['vitest', 'typescript', '@testing-library/react', '@tailwindcss/vite', '@radix-ui/react-one-time-password-field']) {
    assert.ok(!byName.has(name), `${name} is not bundled`)
  }
  assert.deepEqual(
    list.map((p) => p.path),
    list.map((p) => p.path).toSorted(),
    'sorted by path',
  )
})

test('a module belongs to the package after its last node_modules', () => {
  assert.equal(packageDirOf('/ui/node_modules/react/cjs/react.production.js'), '/ui/node_modules/react')
  assert.equal(packageDirOf('/ui/node_modules/@radix-ui/react-dialog/dist/index.mjs'), '/ui/node_modules/@radix-ui/react-dialog')
  assert.equal(packageDirOf('/ui/node_modules/a/node_modules/@s/b/x.js'), '/ui/node_modules/a/node_modules/@s/b')
  assert.equal(packageDirOf('/ui/src/main.tsx'), undefined)
})

test('stylesheets reference packages by @import and @plugin, comments aside', () => {
  const css = `@import "tailwindcss";\n@import 'tw-animate-css' layer(base);\n/* @import "commented-out"; */\n@import url("./local.css");\n@plugin "@tailwindcss/typography";\n`
  assert.deepEqual(cssRefs(css), ['tailwindcss', 'tw-animate-css', './local.css', '@tailwindcss/typography'])
})
