// The npm packages the web UI bundle contains, from Vite's module graph at build time: the image SBOM
// lists them and the licence check runs over them (scripts/prodtree.mjs). A package is bundled when
//   - a module of it renders code into an output chunk (tree-shaken modules do not count);
//   - it ships a stylesheet in the module graph, or a stylesheet there imports its CSS (@import or
//     @plugin), directly or through another package's CSS: Tailwind inlines those itself, outside
//     the module graph;
//   - it provides a virtual helper module rendered into a chunk (Vite's preload helper and
//     modulepreload polyfill, Rolldown's runtime).
// A rendered module that is neither the UI's own source nor attributable to a package fails the build,
// so the list never silently misses one.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Plugin } from 'vite'

// BundledPackage is one bundled package: path is its directory below ui/, as the lockfile keys it.
export interface BundledPackage {
  path: string
  name: string
  version: string
  license: string
}

const UI = fileURLToPath(new URL('..', import.meta.url))

// MANIFEST is where a build writes the bundled packages: next to the embedded dist directory, so it
// is not embedded itself.
export const MANIFEST = fileURLToPath(new URL('../../internal/web/ui/bundle-packages.json', import.meta.url))

// VIRTUAL_PACKAGES is the package behind each virtual module a build may render, by ID prefix.
const VIRTUAL_PACKAGES: readonly (readonly [string, string])[] = [
  ['\0vite/', 'vite'],
  ['\0rolldown/', 'rolldown'],
]

const NODE_MODULES = '/node_modules/'

// packageDirOf is the directory of the package a file belongs to (its last node_modules segment and
// the package name after it, scoped or not); undefined outside node_modules.
export function packageDirOf(file: string): string | undefined {
  const i = file.lastIndexOf(NODE_MODULES)
  if (i < 0) return undefined
  const parts = file.slice(i + NODE_MODULES.length).split('/')
  const n = parts[0]?.startsWith('@') ? 2 : 1
  if (parts.length < n || parts.slice(0, n).some((p) => p === '')) return undefined
  return file.slice(0, i + NODE_MODULES.length) + parts.slice(0, n).join('/')
}

// findPackageDir resolves a package name the way Node does, from directory from upwards.
export function findPackageDir(name: string, from: string): string | undefined {
  for (let dir = from; ; dir = dirname(dir)) {
    const candidate = join(dir, 'node_modules', name)
    if (existsSync(join(candidate, 'package.json'))) return candidate
    if (dirname(dir) === dir) return undefined
  }
}

// licenseOf is a package.json's licence: the SPDX expression, or the type of a legacy licence object
// or list; "" when it has none.
function licenseOf(pkg: { license?: unknown; licenses?: unknown }): string {
  const type = (l: unknown) => (typeof l === 'string' ? l : typeof l === 'object' && l !== null && 'type' in l ? String(l.type) : '')
  if (pkg.license !== undefined) return type(pkg.license)
  if (Array.isArray(pkg.licenses)) return pkg.licenses.map(type).filter(Boolean).join(' OR ')
  return ''
}

function readJSON(file: string): Record<string, unknown> {
  return JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
}

// packageAt reads the package in dir.
function packageAt(dir: string): BundledPackage {
  const pkg = readJSON(join(dir, 'package.json'))
  return { path: relative(UI, dir).split(sep).join('/'), name: String(pkg.name ?? ''), version: String(pkg.version ?? ''), license: licenseOf(pkg) }
}

const COMMENT = /\/\*[\s\S]*?\*\//g
const CSS_REF = /@(?:import|plugin)\s+(?:url\(\s*)?(['"])([^'"]+)\1/g

// cssRefs are the specifiers a stylesheet imports (@import) or loads as a Tailwind plugin (@plugin).
export function cssRefs(css: string): string[] {
  return [...css.replace(COMMENT, '').matchAll(CSS_REF)].map((m) => m[2] ?? '')
}

// isBare reports whether a specifier names a package rather than a path or URL.
function isBare(spec: string): boolean {
  return !/^(\.|\/|#|[a-z][a-z0-9+.-]*:)/i.test(spec)
}

// packageName splits a bare specifier into the package name and the subpath after it.
function packageName(spec: string): [string, string] {
  const parts = spec.split('/')
  const n = spec.startsWith('@') ? 2 : 1
  return [parts.slice(0, n).join('/'), parts.slice(n).join('/')]
}

// styleEntry is the stylesheet a bare CSS import of a package resolves to, as Tailwind resolves it
// (the "style" export condition, then the style field, then the subpath as a file); undefined when
// it names no stylesheet, as a @plugin does.
function styleEntry(dir: string, subpath: string): string | undefined {
  const pkg = readJSON(join(dir, 'package.json'))
  const key = subpath === '' ? '.' : `./${subpath}`
  const exp = pkg.exports
  let target: unknown
  if (typeof exp === 'object' && exp !== null && !Array.isArray(exp)) {
    const keyed = Object.keys(exp).some((k) => k.startsWith('.'))
    const entry = keyed ? (exp as Record<string, unknown>)[key] : key === '.' ? exp : undefined
    target = typeof entry === 'object' && entry !== null ? (entry as Record<string, unknown>).style : entry
  } else if (typeof exp === 'string' && key === '.') {
    target = exp
  }
  if (target === undefined && key === '.') target = pkg.style
  if (target === undefined && key !== '.') target = subpath
  if (typeof target !== 'string' || !target.endsWith('.css')) return undefined
  const file = resolve(dir, target)
  return existsSync(file) ? file : undefined
}

// cssPackages are the directories of the packages a stylesheet imports, through package CSS too.
export function cssPackages(file: string, seen = new Set<string>()): string[] {
  if (seen.has(file)) return []
  seen.add(file)
  const out: string[] = []
  for (const spec of cssRefs(readFileSync(file, 'utf8'))) {
    if (!isBare(spec)) {
      const local = resolve(dirname(file), spec.split('?')[0] ?? '')
      if (spec.startsWith('.') && local.endsWith('.css') && existsSync(local)) out.push(...cssPackages(local, seen))
      continue
    }
    const [name, subpath] = packageName(spec)
    const dir = findPackageDir(name, dirname(file))
    if (!dir) throw new Error(`${file}: cannot resolve the package of ${spec}`)
    out.push(dir)
    const entry = styleEntry(dir, subpath)
    if (entry) out.push(...cssPackages(entry, seen))
  }
  return out
}

// isUISource reports whether a file is the UI's own source rather than a package's.
function isUISource(file: string): boolean {
  const rel = relative(UI, file)
  return !rel.startsWith('..') && !rel.split(sep).includes('node_modules')
}

export interface BundledOptions {
  // manifest is where the list is written when the build writes its output.
  manifest?: string
  // onPackages receives the list, sorted by path, whether or not it is written.
  onPackages?: (packages: BundledPackage[]) => void
}

// bundledPackages is the Vite plugin that lists the bundled packages, writing them to the manifest
// as JSON whenever the build writes its output.
export function bundledPackages({ manifest = MANIFEST, onPackages }: BundledOptions = {}): Plugin {
  let write = true
  return {
    name: 'ffs:bundled-packages',
    apply: 'build',
    configResolved(config) {
      write = config.build.write
    },
    generateBundle(_options, bundle) {
      if (!write && !onPackages) return
      const found = new Map<string, BundledPackage>()
      const add = (dir: string) => {
        if (!found.has(dir)) found.set(dir, packageAt(dir))
      }
      const vite = findPackageDir('vite', UI)
      const unattributed: string[] = []
      for (const out of Object.values(bundle)) {
        if (out.type !== 'chunk') continue
        for (const [id, m] of Object.entries(out.modules)) {
          if (m.renderedLength === 0) continue
          const file = id.split('?')[0] ?? id
          if (file.startsWith('\0')) {
            const name = VIRTUAL_PACKAGES.find(([prefix]) => file.startsWith(prefix))?.[1]
            const dir = name && vite ? findPackageDir(name, vite) : undefined
            if (dir) add(dir)
            else unattributed.push(id)
            continue
          }
          const dir = packageDirOf(file)
          if (dir && existsSync(join(dir, 'package.json'))) add(dir)
          else if (!isUISource(file)) unattributed.push(id)
        }
      }
      // Stylesheets render no code into chunks: each one in the graph counts, with its own package
      // when a package ships it, and the packages it imports.
      for (const id of this.getModuleIds()) {
        const file = id.split('?')[0] ?? id
        if (file.startsWith('\0') || !file.endsWith('.css') || !existsSync(file)) continue
        const own = packageDirOf(file)
        if (own && existsSync(join(own, 'package.json'))) add(own)
        cssPackages(file).forEach(add)
      }
      if (unattributed.length > 0) this.error(`bundled modules of no known package: ${unattributed.join(', ')}`)
      const list = [...found.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
      onPackages?.(list)
      if (write) {
        mkdirSync(dirname(manifest), { recursive: true })
        writeFileSync(manifest, `${JSON.stringify(list, null, 2)}\n`)
      }
    },
  }
}

// bundledPackageList builds the UI in memory, writing nothing, and returns the packages the bundle
// contains: the list a build writes to the manifest.
export async function bundledPackageList(): Promise<BundledPackage[]> {
  const { build } = await import('vite')
  let list: BundledPackage[] | undefined
  await build({
    root: UI,
    configFile: join(UI, 'vite.config.ts'),
    logLevel: 'error',
    build: { write: false },
    plugins: [bundledPackages({ onPackages: (l) => (list = l) })],
  })
  if (!list) throw new Error('the build listed no bundled packages')
  return list
}

// readManifest reads the bundled packages a build wrote.
export function readManifest(manifest = MANIFEST): BundledPackage[] {
  if (!existsSync(manifest)) throw new Error(`${manifest} is missing: run npm run build first`)
  return JSON.parse(readFileSync(manifest, 'utf8')) as BundledPackage[]
}
