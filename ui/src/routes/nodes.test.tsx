import { screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { copy } from '@/lib/copy'
import { mockApi, problem } from '@/test/api'
import { agentStatus, counts, findingsPage, imagePackagesPage, nodeDetail, nodeGroupDetail, nodeGroupRow, nodeGroupsList } from '@/test/fixtures'
import { renderApp } from '@/test/render'

test('without the agent the nodes page lists nodeinfo groups and the agent-missing copy', async () => {
  mockApi().on('/nodegroups', nodeGroupsList({ agentEnabled: false, groups: [nodeGroupRow({ id: 'n1', kind: 'nodeinfo', label: 'worker pool', members: 2 })] }))
  renderApp('/nodes')
  expect(await screen.findByText(copy.agentMissing)).toBeInTheDocument()
  expect(screen.getByRole('link', { name: /worker pool/ })).toHaveAttribute('href', '/nodegroups/n1')
  expect(screen.getByRole('link', { name: /Control plane/ })).toHaveAttribute('href', '/controlplane')
  expect(screen.queryByRole('columnheader', { name: 'Agents' })).toBeNull()
})

test.each(['hostPackages', 'kernel', 'cachedImages'] as const)('the %s view shows the agent-missing copy without agent data', async (view) => {
  const api = mockApi().on('/nodegroups/{id}', nodeGroupDetail({ agentData: false }))
  renderApp(`/nodegroups/n1?view=${view}`)
  expect(await screen.findByText(copy.agentMissing)).toBeInTheDocument()
  expect(api.calls('/images/{digest}/packages')).toHaveLength(0)
})

test('host packages are searched through the node group digest when the agent reports', async () => {
  const api = mockApi().on('/nodegroups/{id}', nodeGroupDetail({ agentData: true })).on('/images/{digest}/packages', imagePackagesPage())
  renderApp('/nodegroups/g1?view=hostPackages')
  await waitFor(() => expect(api.calls('/images/{digest}/packages')[0]?.pathname).toBe('/api/v1/images/nodegroup%3Ag1/packages'))
})

test('a missing node group falls back to /nodes', async () => {
  mockApi().on('/nodegroups/{id}', problem(404, 'not_found', 'node group g9 not found')).on('/nodegroups', nodeGroupsList())
  const { router } = renderApp('/nodegroups/g9')
  await waitFor(() => expect(router.state.location.pathname).toBe('/nodes'))
})

test('compare writes the URL and shows the drift detail', async () => {
  const api = mockApi().on('/nodegroups/{id}', (u) =>
    nodeGroupDetail({
      agentData: true,
      drift: [
        {
          other: { id: 'g2', label: 'worker pool b', kind: 'agent' },
          summary: 'kernel differs',
          fields: [{ field: 'kernelRelease', from: '6.8.0-45', to: '6.8.0-41' }],
          packagesCompared: true,
          newerHere: 0,
          newerThere: 3,
          onlyHere: 1,
          onlyThere: 0,
        },
      ],
      // API orientation: from = the other group, to = this group (page g1)
      compare: u.searchParams.get('compare')
        ? {
            from: 'g2',
            to: 'g1',
            fields: [{ field: 'kernelRelease', from: '6.8.0-45', to: '6.8.0-41' }],
            packagesCompared: true,
            onlyFrom: [],
            onlyTo: [],
            changed: [{ ecosystem: 'deb', name: 'openssl', arch: 'amd64', from: '3.5.2-1', to: '3.5.1-1', newer: 'from' }],
          }
        : undefined,
    }),
  )
  const { router, user } = renderApp('/nodegroups/g1?view=members')
  await user.click(await screen.findByRole('link', { name: 'Compare with worker pool b' }))
  expect(router.state.location.search).toEqual({ view: 'members', compare: 'g2' })
  expect(await screen.findByText('6.8.0-45')).toBeInTheDocument()
  // Other group, then This group
  expect(
    within(screen.getByRole('row', { name: /kernelRelease/ }))
      .getAllByRole('cell')
      .map((c) => c.textContent),
  ).toEqual(['kernelRelease', '6.8.0-45', '6.8.0-41'])
  expect(within(screen.getByRole('row', { name: /openssl/ })).getByText(copy.nodes.newer.from)).toBeInTheDocument()
  expect(api.calls('/nodegroups/{id}').at(-1)!.searchParams.get('compare')).toBe('g2')
})

test('a node without agent data shows the agent-missing copy for agent status and cached images', async () => {
  mockApi().on('/nodes/{name}', nodeDetail({ agent: agentStatus({ state: 'never' }), group: { id: 'g1', label: 'worker pool', kind: 'nodeinfo' } }))
  renderApp('/nodes/worker-1')
  expect(await screen.findByRole('heading', { level: 1, name: 'worker-1' })).toBeInTheDocument()
  expect(screen.getAllByText(copy.agentMissing)).toHaveLength(2)
  expect(screen.getByRole('link', { name: 'worker pool' })).toHaveAttribute('href', '/nodegroups/g1')
})

test('the control plane page lists Kubernetes versions and its findings by fix', async () => {
  const api = mockApi()
    .on(
      '/nodegroups',
      nodeGroupsList({
        controlPlane: {
          kubernetes: [{ version: '1.35.1', nodes: 3 }],
          runtimes: [{ name: 'containerd', version: '2.1.4', nodes: 3 }],
          counts: counts({ high: 2 }),
          fixable: 2,
          suggestions: [],
        },
      }),
    )
    .on('/findings', findingsPage())
  renderApp('/controlplane')
  expect(await screen.findByText('1.35.1')).toBeInTheDocument()
  expect(screen.getByText('containerd')).toBeInTheDocument()
  await waitFor(() => expect(api.calls('/findings')[0].searchParams.get('scope')).toBe('controlplane'))
})
