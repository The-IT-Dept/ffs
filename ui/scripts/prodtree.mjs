// Supply-chain checks over package-lock.json alone (lockfile v3):
//   licenses         fail on a production package whose licence is missing or GPL-family, SSPL or EUPL;
//   scripts          fail on any package with an install script that is not allowlisted below;
//   manifests <dir>  write <dir>/<lockfile key>/package.json = {name, version, license} for every
//                    production package, so an SBOM scanner finds the packages bundled into the UI.
// A production (non-dev) package is a lockfile entry with neither "dev" nor "devOptional".
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const ALLOWED_INSTALL_SCRIPTS = [
  {
    name: 'fsevents',
    reason: 'optional macOS file watcher pulled in by vite; dev-only; never executed because .npmrc sets ignore-scripts=true',
  },
]

const FORBIDDEN_LICENSE = /GPL|SSPL|EUPL/i

const lockPath = fileURLToPath(new URL('../package-lock.json', import.meta.url))
const lock = JSON.parse(readFileSync(lockPath, 'utf8'))
if (lock.lockfileVersion !== 3) {
  console.error(`package-lock.json: lockfileVersion ${lock.lockfileVersion}, want 3`)
  process.exit(1)
}

const entries = Object.entries(lock.packages ?? {}).filter(([key]) => key !== '')
const production = entries.filter(([, e]) => !e.dev && !e.devOptional)

function nameOf(key, entry) {
  if (entry.name) return entry.name
  const i = key.lastIndexOf('node_modules/')
  return i < 0 ? key : key.slice(i + 'node_modules/'.length)
}

function licenses() {
  const bad = production.filter(([, e]) => !e.license || FORBIDDEN_LICENSE.test(String(e.license)))
  for (const [key, e] of bad) console.error(`${key} ${e.version ?? ''}: licence ${e.license ?? 'missing'}`)
  if (bad.length > 0) process.exit(1)
  console.log(`licences: ${production.length} production packages checked`)
}

function scripts() {
  const allowed = new Set(ALLOWED_INSTALL_SCRIPTS.map((a) => a.name))
  const bad = entries.filter(([key, e]) => e.hasInstallScript && !allowed.has(nameOf(key, e)))
  for (const [key, e] of bad) console.error(`${key} ${e.version ?? ''}: install script not allowlisted`)
  if (bad.length > 0) process.exit(1)
  console.log(`install scripts: ${entries.length} packages checked`)
}

function manifests(dir) {
  if (!dir) {
    console.error('usage: prodtree.mjs manifests <dir>')
    process.exit(2)
  }
  for (const [key, e] of production) {
    const out = join(dir, key)
    mkdirSync(out, { recursive: true })
    const manifest = { name: nameOf(key, e), version: e.version, license: e.license }
    writeFileSync(join(out, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`)
  }
  console.log(`manifests: ${production.length} written to ${dir}`)
}

const [command, arg] = process.argv.slice(2)
switch (command) {
  case 'licenses':
    licenses()
    break
  case 'scripts':
    scripts()
    break
  case 'manifests':
    manifests(arg)
    break
  default:
    console.error('usage: prodtree.mjs licenses | scripts | manifests <dir>')
    process.exit(2)
}
