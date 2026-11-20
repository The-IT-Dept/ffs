// Empties internal/web/ui/dist before a build, keeping the tracked .keep file, so go:embed never
// picks up assets from an earlier build. vite runs with emptyOutDir false for the same reason. It
// also removes the bundled-packages manifest of an earlier build, which the build writes anew.
import { mkdirSync, readdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MANIFEST } from './bundled.ts'

const dist = fileURLToPath(new URL('../../internal/web/ui/dist', import.meta.url))

mkdirSync(dist, { recursive: true })
for (const entry of readdirSync(dist)) {
  if (entry === '.keep') continue
  rmSync(join(dist, entry), { recursive: true, force: true })
}
rmSync(MANIFEST, { force: true })
