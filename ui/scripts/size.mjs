// Sums the gzip size of every file in internal/web/ui/dist and fails the build when the embedded
// UI would add more than 2,000,000 bytes, gzipped, to the binary.
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'

const BUDGET = 2_000_000
const dist = fileURLToPath(new URL('../../internal/web/ui/dist', import.meta.url))

function* files(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) yield* files(path)
    else if (entry.isFile() && entry.name !== '.keep') yield path
  }
}

let total = 0
for (const path of files(dist)) {
  total += gzipSync(readFileSync(path), { level: 9 }).length
}

console.log(`ui bundle: ${Math.ceil(total / 1000)} kB gzip (budget ${BUDGET / 1000} kB)`)
if (total > BUDGET) {
  console.error(`ui bundle is over budget by ${total - BUDGET} bytes`)
  process.exit(1)
}
