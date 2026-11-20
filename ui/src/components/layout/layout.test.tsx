import { screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import { copy } from '@/lib/copy'
import { mockApi } from '@/test/api'
import { coverageFigure, feedFreshness } from '@/test/fixtures'
import { renderApp, renderWithRouter } from '@/test/render'
import { EmptyState } from './EmptyState'
import { ThemeToggle } from './ThemeToggle'

test('an empty view leads with coverage when ffs cannot see every image', async () => {
  renderWithRouter(<EmptyState coverage={coverageFigure({ inUse: 7, seenInto: 5, full: 4 })} />)
  expect(await screen.findByText('ffs cannot see into 2 of 7 images yet, so this may not be everything.')).toBeInTheDocument()
  expect(screen.queryByText('Nothing needs attention.')).toBeNull()
})

test('an empty view leads with a matching feed that is out of date and links the feeds page', async () => {
  renderWithRouter(<EmptyState coverage={coverageFigure()} feeds={feedFreshness({ fresh: false, stale: ['osv', 'kev'] })} />)
  const mark = await screen.findByText('feed out of date: osv')
  expect(mark.closest('.hatched')).not.toBeNull()
  expect(screen.getByText(copy.feedFirst(1))).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Feeds' })).toHaveAttribute('href', '/feeds')
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('a feed that has never synced counts as out of date', async () => {
  renderWithRouter(<EmptyState feeds={feedFreshness({ fresh: false, stale: ['grypedb', 'osv'], oldestSuccess: null })} />)
  expect(await screen.findByText('feed out of date: grypedb, osv')).toBeInTheDocument()
  expect(screen.getByText(copy.feedFirst(2))).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('a stale ranking feed alone does not stop an empty view from reading clean', async () => {
  renderWithRouter(<EmptyState coverage={coverageFigure()} feeds={feedFreshness({ fresh: false, stale: ['kev', 'epss'] })} />)
  expect(await screen.findByText(copy.empty)).toBeInTheDocument()
  expect(screen.queryByRole('link', { name: 'Feeds' })).toBeNull()
})

test('the coverage link of an empty view carries its scope', async () => {
  renderWithRouter(<EmptyState coverage={coverageFigure({ inUse: 7, seenInto: 5, full: 4 })} scope={{ kind: 'namespace', value: 'shop' }} />)
  expect(await screen.findByRole('link', { name: 'Coverage' })).toHaveAttribute('href', '/coverage?scope=namespace:shop')
})

test('a lead the caller knows about replaces nothing needs attention', async () => {
  renderWithRouter(<EmptyState coverage={coverageFigure()} lead={<p>node agent cannot read host paths</p>} />)
  expect(await screen.findByText('node agent cannot read host paths')).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
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
