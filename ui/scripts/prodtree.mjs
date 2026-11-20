// Supply-chain checks over the packages the web UI bundle contains (scripts/bundled.ts, from Vite's
// module graph) and over package-lock.json:
//   licenses         build the UI in memory and fail on a bundled package whose licence is missing
//                    or GPL-family, SSPL or EUPL;
//   scripts          fail on any lockfile package with an install script that is not allowlisted below;
//   manifests <dir>  after npm run build, check the licences of the packages the build listed and write
//                    <dir>/<path>/package.json = {name, version, license} for each, so an SBOM scanner
//                    finds the packages bundled into the UI.
// The licence check and the manifests cover the same set: the one the bundledPackages plugin lists.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { bundledPackageList, readManifest } from './bundled.ts'

export const ALLOWED_INSTALL_SCRIPTS = [
  {
    name: 'fsevents',
    reason: 'optional macOS file watcher pulled in by vite; dev-only; never executed because .npmrc sets ignore-scripts=true',
  },
]

const FORBIDDEN_LICENSE = /GPL|SSPL|EUPL/i

// checkLicences fails on a package whose licence is missing or forbidden.
function checkLicences(packages) {
  const bad = packages.filter((p) => !p.license || FORBIDDEN_LICENSE.test(p.license))
  for (const p of bad) console.error(`${p.path} ${p.version}: licence ${p.license || 'missing'}`)
  if (bad.length > 0) process.exit(1)
}

async function licenses() {
  const packages = await bundledPackageList()
  checkLicences(packages)
  console.log(`licences: ${packages.length} bundled packages checked`)
}

function nameOf(key, entry) {
  if (entry.name) return entry.name
  const i = key.lastIndexOf('node_modules/')
  return i < 0 ? key : key.slice(i + 'node_modules/'.length)
}

function scripts() {
  const lock = JSON.parse(readFileSync(fileURLToPath(new URL('../package-lock.json', import.meta.url)), 'utf8'))
  if (lock.lockfileVersion !== 3) {
    console.error(`package-lock.json: lockfileVersion ${lock.lockfileVersion}, want 3`)
    process.exit(1)
  }
  const entries = Object.entries(lock.packages ?? {}).filter(([key]) => key !== '')
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
  const packages = readManifest()
  checkLicences(packages)
  for (const p of packages) {
    const out = join(dir, p.path)
    mkdirSync(out, { recursive: true })
    const manifest = { name: p.name, version: p.version, license: p.license }
    writeFileSync(join(out, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`)
  }
  console.log(`manifests: ${packages.length} written to ${dir}`)
}

const [command, arg] = process.argv.slice(2)
try {
  switch (command) {
    case 'licenses':
      await licenses()
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
} catch (err) {
  console.error(err instanceof Error ? err.message : err)
  process.exit(1)
}
