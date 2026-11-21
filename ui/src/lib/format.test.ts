import { expect, test } from 'vitest'
import { NOW } from '@/test/fixtures'
import { eolText, eolWarns, formatAge, formatBytes, formatCompact, formatCount, formatPercent, plural, shortDigest } from './format'

test('formats counts, percentages, ages and digests', () => {
  expect(formatCount(1356)).toBe('1,356')
  expect(formatCompact(999)).toBe('999')
  expect(formatCompact(6512)).toBe('6.5k')
  expect(formatCompact(1_240_000)).toBe('1.2M')
  expect(formatPercent(0.1)).toBe('10%')
  expect(formatPercent(0.004)).toBe('0.4%')
  expect(formatPercent(0.0004)).toBe('0.04%')
  expect(formatPercent(0.123)).toBe('12.3%')
  const now = new Date(NOW)
  expect(formatAge('2026-11-18T23:59:40Z', now)).toBe('now')
  expect(formatAge('2026-11-18T23:15:00Z', now)).toBe('45 min')
  expect(formatAge('2026-11-18T22:00:00Z', now)).toBe('2 h')
  expect(formatAge('2026-11-16T00:00:00Z', now)).toBe('3 d')
  expect(formatAge('2026-07-22T00:00:00Z', now)).toBe('2026-07-22')
  expect(shortDigest('sha256:' + 'a'.repeat(64))).toBe('sha256:aaaaaaaaaaaa')
  expect(shortDigest('unknown:ghcr.io/example/private:1.0')).toBe('unknown:ghcr.io/example/private:1.0')
  expect(formatBytes(1536)).toBe('1.5 KiB')
  expect(plural(1, 'finding', 'findings')).toBe('1 finding')
})

test('eolText is the lifecycle text, else the override note', () => {
  const e = { product: 'alpine', cycle: 'rolling', eolDate: '', isEol: false, latest: '', note: 'rolling release', text: '' }
  expect(eolText(e)).toBe('rolling release')
  expect(eolText({ ...e, text: 'Alpine Linux: rolling release' })).toBe('Alpine Linux: rolling release')
  expect(eolText({ ...e, note: '' })).toBe('')
  expect(eolText(undefined)).toBe('')
})

// W42: end of life past, or at most 90 days away, warns; a later date, a note or no status does not.
test('eolWarns marks an end of life that has passed or is near', () => {
  const now = Date.parse(NOW)
  const e = { product: 'kubernetes', cycle: '1.35', eolDate: '', isEol: false, latest: '', note: '', text: '' }
  expect(eolWarns({ ...e, isEol: true }, now)).toBe(true)
  expect(eolWarns({ ...e, eolDate: '2026-10-27' }, now)).toBe(true)
  expect(eolWarns({ ...e, eolDate: '2027-02-16' }, now)).toBe(true)
  expect(eolWarns({ ...e, eolDate: '2027-02-18' }, now)).toBe(false)
  expect(eolWarns({ ...e, note: 'rolling release' }, now)).toBe(false)
  expect(eolWarns(undefined, now)).toBe(false)
})
