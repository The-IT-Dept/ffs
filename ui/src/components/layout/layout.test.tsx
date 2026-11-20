import { screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import { mockApi } from '@/test/api'
import { coverageFigure } from '@/test/fixtures'
import { renderApp, renderWithRouter } from '@/test/render'
import { EmptyState } from './EmptyState'
import { ThemeToggle } from './ThemeToggle'

test('an empty view leads with coverage when ffs cannot see every image', async () => {
  renderWithRouter(<EmptyState coverage={coverageFigure({ inUse: 7, seenInto: 5, full: 4 })} />)
  expect(await screen.findByText('ffs cannot see into 2 of 7 images yet, so this may not be everything.')).toBeInTheDocument()
  expect(screen.queryByText('Nothing needs attention.')).toBeNull()
})

test('the theme toggle cycles light, dark and system and stores ffs-theme', async () => {
  const { user } = renderWithRouter(<ThemeToggle />)
  const btn = await screen.findByRole('button', { name: 'Theme: System' })
  await user.click(btn)
  expect(localStorage.getItem('ffs-theme')).toBe('light')
  expect(document.documentElement).not.toHaveClass('dark')
  await user.click(btn)
  expect(localStorage.getItem('ffs-theme')).toBe('dark')
  expect(document.documentElement).toHaveClass('dark')
  await user.click(btn)
  expect(localStorage.getItem('ffs-theme')).toBe('system')
  expect(document.documentElement).not.toHaveClass('dark')
})

test('an unknown path renders the not-found copy', async () => {
  mockApi()
  renderApp('/no/such/page')
  expect(await screen.findByText('That page does not exist.')).toBeInTheDocument()
})
