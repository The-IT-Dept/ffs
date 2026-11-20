import { describe, expect, it } from 'vitest'
import { cn } from './utils'

describe('cn', () => {
  it('cn merges conflicting Tailwind classes', () => {
    expect(cn('px-2 text-sm', false && 'hidden', 'px-4')).toBe('text-sm px-4')
  })

  it('no component imports the cn package', () => {
    const files = import.meta.glob('../components/ui/*.tsx', { query: '?raw', import: 'default', eager: true }) as Record<string, string>
    expect(Object.keys(files).length).toBe(19)
    for (const [name, src] of Object.entries(files)) expect(src, name).not.toMatch(/from ["']cn["']/)
  })
})
