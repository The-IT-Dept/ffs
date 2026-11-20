import { expect, test } from 'vitest'
import { NOW } from '@/test/fixtures'
import { formatAge, formatBytes, formatCompact, formatCount, formatPercent, plural, shortDigest } from './format'

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
