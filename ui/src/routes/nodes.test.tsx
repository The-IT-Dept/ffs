import { act, screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { copy } from '@/lib/copy'
import type { S } from '@/api/types'
import { mockApi, problem } from '@/test/api'
import {
  agentStatus,
  counts,
  findingsPage,
  fixAction,
  groupRow,
  imagePackagesPage,
  nodeDetail,
  nodeGroupDetail,
  nodeGroupRow,
  nodeGroupsList,
  scopeCard,
  workloadsPage,
} from '@/test/fixtures'
import { renderApp } from '@/test/render'

function member(name: string, agent: S<'AgentStatus'>): S<'NodeRow'> {
  return { name, ready: true, exposed: false, agent }
}

const blocked = agentStatus({ gaps: [{ code: 'node_agent_blocked', detail: 'permission denied' }] })

test('without the agent the nodes page lists nodeinfo groups and the agent-missing copy', async () => {
  mockApi().on('/nodegroups', nodeGroupsList({ agentEnabled: false, groups: [nodeGroupRow({ id: 'n1', kind: 'nodeinfo', label: 'worker pool', members: 2 })] }))
  renderApp('/nodes')
  expect(await screen.findByText(copy.agentMissing)).toBeInTheDocument()
  // Linked by its stable name, which survives the package updates that re-key a group.
  expect(screen.getByRole('link', { name: /worker pool/ })).toHaveAttribute('href', '/nodegroups/worker-pool-a')
  expect(screen.getByRole('link', { name: /Control plane/ })).toHaveAttribute('href', '/controlplane')
  expect(screen.queryByRole('columnheader', { name: 'Agents' })).toBeNull()
})

test.each(['hostPackages', 'kernel', 'cachedImages'] as const)('the %s view shows the agent-missing copy without agent data', async (view) => {
  const api = mockApi().on('/nodegroups/{id}', nodeGroupDetail({ agentData: false }))
  renderApp(`/nodegroups/n1?view=${view}`)
  expect(await screen.findByText(copy.agentMissing)).toBeInTheDocument()
  expect(api.calls('/images/{digest}/packages')).toHaveLength(0)
})

test('a node group without agent data says the agent is missing instead of nothing needs attention', async () => {
  const api = mockApi().on('/nodegroups/{id}', nodeGroupDetail({ agentData: false })).on('/findings', findingsPage())
  renderApp('/nodegroups/worker-pool-a')
  expect(await screen.findByText(copy.agentMissing)).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
  // The page is asked by the stable name; its findings by the ID the detail resolved it to.
  expect(api.calls('/nodegroups/{id}')[0].pathname).toBe('/api/v1/nodegroups/worker-pool-a')
  expect(api.calls('/findings')[0].searchParams.get('scope')).toBe('nodegroup:g1')
})

test('a node group with agent data and no findings says nothing needs attention', async () => {
  mockApi().on('/nodegroups/{id}', nodeGroupDetail({ agentData: true })).on('/findings', findingsPage())
  renderApp('/nodegroups/g1')
  expect(await screen.findByText(copy.empty)).toBeInTheDocument()
  expect(screen.queryByText(copy.agentMissing)).toBeNull()
})

test('host packages are searched through the node group digest when the agent reports', async () => {
  const api = mockApi().on('/nodegroups/{id}', nodeGroupDetail({ agentData: true })).on('/images/{digest}/packages', imagePackagesPage())
  renderApp('/nodegroups/g1?view=hostPackages')
  await waitFor(() => expect(api.calls('/images/{digest}/packages')[0]?.pathname).toBe('/api/v1/images/nodegroup%3Ag1/packages'))
})

test('a missing node group falls back to /nodes with a notice', async () => {
  mockApi().on('/nodegroups/{id}', problem(404, 'not_found', 'node group g9 not found')).on('/nodegroups', nodeGroupsList())
  const { router } = renderApp('/nodegroups/g9')
  await waitFor(() => expect(router.state.location.pathname).toBe('/nodes'))
  expect(await screen.findByRole('status')).toHaveTextContent(copy.gone('nodegroup'))
})

test('an explorer scoped to a node group that no longer exists hands over to /nodes with the same notice', async () => {
  mockApi().on('/findings', problem(404, 'not_found', 'node group g9 not found')).on('/nodegroups', nodeGroupsList())
  const { router } = renderApp('/vulnerabilities?scope=nodegroup:g9')
  await waitFor(() => expect(router.state.location.pathname).toBe('/nodes'))
  expect(await screen.findByRole('status')).toHaveTextContent('That node group no longer exists.')
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('an explorer scoped to a workload that no longer exists hands over to /workloads with a notice', async () => {
  mockApi().on('/images', problem(404, 'not_found', 'workload not found')).on('/workloads', workloadsPage())
  const { router } = renderApp('/images?scope=workload:Deployment/shop/gone')
  await waitFor(() => expect(router.state.location.pathname).toBe('/workloads'))
  expect(router.state.location.search).toEqual({})
  expect(await screen.findByRole('status')).toHaveTextContent('That workload no longer exists.')
})

test('the notice lasts one page: the next navigation drops it', async () => {
  mockApi().on('/nodegroups/{id}', problem(404, 'not_found', 'gone')).on('/nodegroups', nodeGroupsList()).on('/workloads', workloadsPage())
  const { router } = renderApp('/nodegroups/g9')
  expect(await screen.findByRole('status')).toBeInTheDocument()
  await act(() => router.navigate({ to: '/workloads' }))
  await waitFor(() => expect(screen.queryByRole('status')).toBeNull())
})

test('a node group with a blocked member leads its header and empty findings with the gap, never "nothing needs attention"', async () => {
  mockApi()
    .on('/nodegroups/{id}', nodeGroupDetail({ agentData: true, members: [member('worker-1', blocked), member('worker-2', agentStatus())] }))
    .on('/findings', findingsPage())
  renderApp('/nodegroups/g1')
  const main = await screen.findByRole('main')
  // Under the header, and leading the empty findings.
  await waitFor(() => expect(within(main).getAllByText(copy.gaps.node_agent_blocked.gap)).toHaveLength(2))
  for (const m of within(main).getAllByText(copy.gaps.node_agent_blocked.gap)) expect(m.closest('.hatched')).not.toBeNull()
  expect(within(main).getAllByText('1 of 2 nodes')).toHaveLength(2)
  expect(within(main).getByText(copy.gaps.node_agent_blocked.todo)).toBeInTheDocument()
  expect(within(main).queryByText(copy.empty)).toBeNull()
})

test('a node group with gaps leads its findings and host packages with them', async () => {
  mockApi()
    .on('/nodegroups/{id}', nodeGroupDetail({ agentData: true, members: [member('worker-1', agentStatus({ gaps: [{ code: 'no_package_database', detail: '' }] }))] }))
    .on('/findings', findingsPage({ total: 1, groups: 1, findings: 2, groupRows: [groupRow({ key: 'none', findings: 2, distinct: 1, fix: fixAction() })] }))
    .on('/images/{digest}/packages', imagePackagesPage())
  const { user } = renderApp('/nodegroups/g1')
  const note = await screen.findByRole('note')
  expect(within(note).getByText(copy.gaps.no_package_database.gap).closest('.hatched')).not.toBeNull()
  // The note comes before the groups.
  const group = await screen.findByRole('button', { name: /No fix yet/ })
  expect(note.compareDocumentPosition(group) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  await user.click(screen.getByRole('tab', { name: 'Host packages' }))
  expect(within(await screen.findByRole('note')).getByText(copy.gaps.no_package_database.todo)).toBeInTheDocument()
  expect(await screen.findByText(copy.emptyList.hostPackages)).toBeInTheDocument()
})

test('a node group whose members have all gone stale is not read as clean', async () => {
  mockApi()
    .on(
      '/nodegroups/{id}',
      nodeGroupDetail({
        agentData: true,
        members: [
          member('worker-1', agentStatus({ state: 'stale' })),
          member('worker-2', agentStatus({ state: 'stale', gaps: [{ code: 'node_agent_missing', detail: 'last report 2 hours ago' }] })),
        ],
      }),
    )
    .on('/findings', findingsPage())
  renderApp('/nodegroups/g1')
  const main = await screen.findByRole('main')
  await waitFor(() => expect(within(main).getAllByText(copy.nodes.agentStale)).toHaveLength(2))
  expect(within(main).getAllByText('2 of 2 nodes')).toHaveLength(2)
  // One line per gap: a stale agent's missing inventory is the stopped line, not a second one.
  expect(within(main).queryByText(copy.gaps.node_agent_missing.gap)).toBeNull()
  expect(within(main).queryByText(copy.empty)).toBeNull()
})

test.each([
  ['disabled', agentStatus({ state: 'disabled' }), copy.agentMissing],
  ['never reported', agentStatus({ state: 'never' }), copy.gaps.node_agent_missing.gap],
  ['blocked', blocked, copy.gaps.node_agent_blocked.gap],
  ['reporting without a host inventory', agentStatus(), copy.gaps.host_not_inventoried.gap],
  ['unsupported', agentStatus({ state: 'never', gaps: [{ code: 'node_agent_unsupported', detail: 'arm' }] }), copy.gaps.node_agent_unsupported.gap],
] as const)('without agent data a group says why by its agents: %s', async (_, agent, text) => {
  mockApi().on('/nodegroups/{id}', nodeGroupDetail({ agentData: false, members: [member('worker-1', agent)] }))
  renderApp('/nodegroups/g1?view=cachedImages')
  const main = await screen.findByRole('main')
  expect((await within(main).findAllByText(text)).length).toBeGreaterThan(0)
  if (text !== copy.agentMissing) expect(within(main).queryByText(copy.agentMissing)).toBeNull()
  if (text === copy.gaps.node_agent_unsupported.gap) expect(within(main).queryByText(copy.gaps.node_agent_missing.gap)).toBeNull()
})

test('empty lists that are not findings say what is empty', async () => {
  mockApi().on('/nodegroups/{id}', nodeGroupDetail({ agentData: true, cachedImages: [] }))
  renderApp('/nodegroups/g1?view=cachedImages')
  expect(await screen.findByText(copy.emptyList.cachedImages)).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('the nodes page hatches the counts of groups ffs cannot fully see and shows — without a host inventory', async () => {
  mockApi()
    .on(
      '/nodegroups',
      nodeGroupsList({
        groups: [
          nodeGroupRow({ id: 'g1', name: 'ubuntu-24.04-k6.8', label: 'ubuntu a' }),
          nodeGroupRow({ id: 'g2', name: 'rocky-9-k5.14', label: 'rocky b', counts: counts({ urgent: 2 }) }),
          nodeGroupRow({ id: 'g3', name: 'debian-13-k6.12', label: 'debian c', agents: { reporting: 1, reportingWithoutInventory: 0, stale: 1, never: 0, disabled: 0, unsupported: 0 } }),
          nodeGroupRow({ id: 'n1', kind: 'nodeinfo', name: 'talos-1.11', label: 'talos d', agents: { reporting: 0, reportingWithoutInventory: 0, stale: 0, never: 2, disabled: 0, unsupported: 0 } }),
        ],
      }),
    )
    .on(
      '/scope',
      scopeCard({ related: [{ id: 'nodegroups', more: 0, items: [{ scope: 'nodegroup:g2', kind: 'nodegroup', label: 'rocky b', worst: 'urgent', count: 2, gap: true }] }] }),
    )
  renderApp('/nodes')
  const row = async (name: string) => screen.findByRole('row', { name: new RegExp(name) })
  expect((await row('ubuntu a')).querySelector('.hatched')).toBeNull()
  expect(within(await row('ubuntu a')).getByText(copy.nodes.kind.agent)).toBeInTheDocument()
  // The Urgent, High and Fixable cells (10th to 12th) of a group the rail marks.
  await waitFor(async () => expect((await row('rocky b')).querySelectorAll('.hatched')).toHaveLength(3))
  expect(within((await row('rocky b')).querySelectorAll('td')[9]).getByText('2').closest('.hatched')).not.toBeNull()
  expect((await row('debian c')).querySelectorAll('.hatched')).toHaveLength(3)
  const talos = await row('talos d')
  expect(within(talos).getByText(copy.nodes.kind.nodeinfo)).toBeInTheDocument()
  const dashes = within(talos).getAllByText('—')
  expect(dashes).toHaveLength(3)
  for (const d of dashes) expect(d.closest('.hatched')).not.toBeNull()
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

test('a node whose agent never reported says so, hatched, for agent status and cached images', async () => {
  mockApi().on('/nodes/{name}', nodeDetail({ agent: agentStatus({ state: 'never' }), group: { id: 'g1', label: 'worker pool', kind: 'nodeinfo' } }))
  renderApp('/nodes/worker-1')
  expect(await screen.findByRole('heading', { level: 1, name: 'worker-1' })).toBeInTheDocument()
  const marks = screen.getAllByText(copy.gaps.node_agent_missing.gap)
  expect(marks).toHaveLength(2)
  for (const m of marks) expect(m.closest('.hatched')).not.toBeNull()
  expect(screen.getAllByText(copy.gaps.node_agent_missing.todo)).toHaveLength(2)
  expect(screen.queryByText(copy.agentMissing)).toBeNull()
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
