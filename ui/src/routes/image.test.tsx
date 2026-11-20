import { screen, waitFor } from '@testing-library/react'
import { expect, test } from 'vitest'
import { copy } from '@/lib/copy'
import { imagePath } from '@/lib/links'
import { mockApi } from '@/test/api'
import { findingsPage, imageDetail, imagePackagesPage } from '@/test/fixtures'
import { renderApp } from '@/test/render'

const placeholder = 'unknown:ghcr.io/example/private:1.0'

test('a placeholder image page requests one encoded segment and shows why it cannot see in', async () => {
  const api = mockApi()
    .on('/images/{digest}', imageDetail({ digest: placeholder, repo: 'ghcr.io/example/private', status: 'unresolvable', statusReason: 'registry refused access' }))
    .on('/findings', findingsPage())
  renderApp(imagePath(placeholder))
  expect((await screen.findByText(/registry refused access/)).closest('.hatched')).not.toBeNull()
  expect(api.calls('/images/{digest}')[0].pathname).toBe('/api/v1/images/unknown%3Aghcr.io%2Fexample%2Fprivate%3A1.0')
  expect(api.calls('/findings')[0].searchParams.get('scope')).toBe(`image:${placeholder}`)
})

test.each(['unresolvable', 'pending', 'catalogFailed'] as const)('an image that is %s and has no findings leads with coverage, not "nothing needs attention"', async (status) => {
  mockApi()
    .on('/images/{digest}', imageDetail({ digest: placeholder, status, coverage: { class: 'none', unattributedExecutables: 0, rustWithoutAuditable: 0, notes: [], cpeOnly: [], gaps: [] } }))
    .on('/findings', findingsPage())
  renderApp(imagePath(placeholder))
  expect(await screen.findByText(copy.coverageFirst(1, 1))).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('a catalogued image with no findings says nothing needs attention', async () => {
  mockApi()
    .on('/images/{digest}', imageDetail({ digest: 'sha256:' + 'd'.repeat(64) }))
    .on('/findings', findingsPage())
  renderApp(imagePath('sha256:' + 'd'.repeat(64)))
  expect(await screen.findByText(copy.empty)).toBeInTheDocument()
  expect(screen.queryByText(copy.coverageFirst(1, 1))).toBeNull()
})

test('package search is server-side and lives in the URL', async () => {
  const d = 'sha256:' + 'b'.repeat(64)
  const api = mockApi().on('/images/{digest}', imageDetail({ digest: d })).on('/images/{digest}/packages', imagePackagesPage())
  const { router, user } = renderApp(`${imagePath(d)}?view=packages`)
  await user.type(await screen.findByRole('searchbox', { name: 'Search packages' }), 'ssl')
  await waitFor(() => expect(router.state.location.search).toEqual({ view: 'packages', q: 'ssl' }))
  await waitFor(() => expect(api.calls('/images/{digest}/packages').at(-1)!.searchParams.get('q')).toBe('ssl'))
})

test('the SBOM view shows source, tool and hatched coverage gaps', async () => {
  const d = 'sha256:' + 'c'.repeat(64)
  mockApi().on(
    '/images/{digest}',
    imageDetail({
      digest: d,
      sbom: { source: 'attestation', tool: 'syft', toolVersion: '1.57.0' },
      ecosystems: [
        { ecosystem: 'deb', packages: 120 },
        { ecosystem: 'go-module', packages: 40 },
      ],
      coverage: { class: 'partial', unattributedExecutables: 3, rustWithoutAuditable: 0, notes: [], cpeOnly: ['php'], gaps: ['attestation_partial'] },
    }),
  )
  renderApp(`${imagePath(d)}?view=sbom`)
  expect(await screen.findByText('SBOM from attestation · syft 1.57.0')).toBeInTheDocument()
  expect(screen.getByText('attested SBOM lists no executables').closest('.hatched')).not.toBeNull()
  expect(screen.getByText('3 executables without package metadata').closest('.hatched')).not.toBeNull()
  expect(screen.getByText('deb')).toBeInTheDocument()
  expect(screen.getByText('120')).toBeInTheDocument()
})

test('an image with no packages leads with why it may list none', async () => {
  const d = 'sha256:' + 'e'.repeat(64)
  mockApi()
    .on('/images/{digest}', imageDetail({ digest: d, status: 'pending', coverage: { class: 'none', unattributedExecutables: 0, rustWithoutAuditable: 0, notes: [], cpeOnly: [], gaps: ['pending'] } }))
    .on('/images/{digest}/packages', imagePackagesPage())
  renderApp(`${imagePath(d)}?view=packages`)
  expect((await screen.findByText(copy.gaps.pending.gap)).closest('.hatched')).not.toBeNull()
  expect(screen.queryByText(copy.emptyList.packages)).toBeNull()
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('a fully seen image with no packages says its SBOM lists none', async () => {
  const d = 'sha256:' + 'f'.repeat(64)
  mockApi().on('/images/{digest}', imageDetail({ digest: d })).on('/images/{digest}/packages', imagePackagesPage())
  renderApp(`${imagePath(d)}?view=packages`)
  expect(await screen.findByText(copy.emptyList.packages)).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('the SBOM view shows each lifecycle with its note when there is no end-of-life date', async () => {
  const d = 'sha256:' + '1'.repeat(64)
  const eol = { eolDate: '', isEol: false, latest: '', note: '', text: '' }
  mockApi().on(
    '/images/{digest}',
    imageDetail({
      digest: d,
      eol: [
        { ...eol, product: 'wolfi', cycle: 'rolling', note: 'rolling release', text: 'Wolfi: rolling release' },
        { ...eol, product: 'python', cycle: '3.13', eolDate: '2029-10-31', text: 'Python 3.13 supported until 2029-10-31' },
        { ...eol, product: 'azure-linux', cycle: '3.0', note: 'lifecycle published by Microsoft' },
      ],
    }),
  )
  renderApp(`${imagePath(d)}?view=sbom`)
  expect(await screen.findByText(copy.image.lifecycle)).toBeInTheDocument()
  expect(screen.getByText('Wolfi: rolling release')).toBeInTheDocument()
  expect(screen.getByText('Python 3.13 supported until 2029-10-31')).toBeInTheDocument()
  expect(screen.getByText('lifecycle published by Microsoft')).toBeInTheDocument()
})
