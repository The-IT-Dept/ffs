import type { S } from '@/api/types'

const counter = new Intl.NumberFormat('en-US')

export function formatCount(n: number): string {
  return counter.format(n)
}

function trimZeros(s: string): string {
  return s.includes('.') ? s.replace(/0+$/, '').replace(/\.$/, '') : s
}

// formatCompact keeps counts below 1,000 exact and shortens larger ones to one decimal: 6.5k, 1.2M.
export function formatCompact(n: number): string {
  if (Math.abs(n) < 1000) return formatCount(n)
  const k = Math.round(n / 100) / 10
  if (Math.abs(k) < 1000) return `${trimZeros(k.toFixed(1))}k`
  return `${trimZeros((Math.round(n / 100_000) / 10).toFixed(1))}M`
}

// formatPercent shows a fraction as a percentage: two decimals under 1 %, one otherwise, without
// trailing zeros.
export function formatPercent(x: number): string {
  const p = x * 100
  return `${trimZeros(p.toFixed(Math.abs(p) < 1 ? 2 : 1))}%`
}

export function formatDate(iso: string): string {
  const t = new Date(iso)
  return Number.isNaN(t.getTime()) ? iso : t.toISOString().slice(0, 10)
}

// formatAge is how long ago iso was: "now", "45 min", "2 h", "3 d", then the date.
export function formatAge(iso: string, now: Date = new Date()): string {
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return iso
  const s = (now.getTime() - t) / 1000
  if (s < 60) return 'now'
  if (s < 3600) return `${Math.floor(s / 60)} min`
  if (s < 48 * 3600) return `${Math.floor(s / 3600)} h`
  if (s < 90 * 86400) return `${Math.floor(s / 86400)} d`
  return formatDate(iso)
}

// shortDigest shortens a sha256 digest to its first 12 hex digits; other IDs (placeholders) stay whole.
export function shortDigest(d: string): string {
  const m = /^sha256:([0-9a-f]{12})[0-9a-f]*$/.exec(d)
  return m ? `sha256:${m[1]}` : d
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${formatCount(n)} B`
  const units = ['KiB', 'MiB', 'GiB'] as const
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(1)} ${units[i]}`
}

export function plural(n: number, one: string, many: string): string {
  return `${formatCount(n)} ${n === 1 ? one : many}`
}

// eolText is what a lifecycle status says: its text ("Debian 12 supported until 2028-06-30",
// "Alpine Linux: rolling release"), else its override note, else nothing.
export function eolText(e: S<'EOL'> | undefined): string {
  return e ? e.text || e.note : ''
}
