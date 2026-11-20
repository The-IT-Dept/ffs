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
  mockApi().on(
    '/nodegroups',
    nodeGroupsList({ agentEnabled: false, groups: [nodeGroupRow({ id: 'worker-pool-a-nodeinfo', kind: 'nodeinfo', label: 'worker pool', members: 2 })] }),
  )
  renderApp('/nodes')
  expect(await screen.findByText(copy.agentMissing)).toBeInTheDocument()
  // Linked by the key the API gives it, which survives the package updates that re-key a group.
  expect(screen.getByRole('link', { name: /worker pool/ })).toHaveAttribute('href', '/nodegroups/worker-pool-a-nodeinfo')
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
  expect(
    within(await screen.findByRole('note')).getByText('Image-based operating systems have no package database; on any other OS, check nodeAgent.packageDatabases.'),
  ).toBeInTheDocument()
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
  ['reporting without a host inventory', agentStatus(), copy.nodes.hostPending],
  ['unsupported', agentStatus({ state: 'never', gaps: [{ code: 'node_agent_unsupported', detail: 'arm' }] }), copy.gaps.node_agent_unsupported.gap],
] as const)('without agent data a group says why by its agents: %s', async (_, agent, text) => {
  mockApi().on('/nodegroups/{id}', nodeGroupDetail({ agentData: false, members: [member('worker-1', agent)] }))
  renderApp('/nodegroups/g1?view=cachedImages')
  const main = await screen.findByRole('main')
  expect((await within(main).findAllByText(text)).length).toBeGreaterThan(0)
  if (text !== copy.agentMissing) expect(within(main).queryByText(copy.agentMissing)).toBeNull()
  if (text === copy.gaps.node_agent_unsupported.gap) expect(within(main).queryByText(copy.gaps.node_agent_missing.gap)).toBeNull()
})

test('a nodeinfo group whose agents report without a host inventory says the host packages are not inventoried yet, and why', async () => {
  const pending = (detail: string, lastError?: string) =>
    agentStatus({ gaps: [{ code: 'host_not_inventoried', detail }], ...(lastError ? { lastError } : {}) })
  mockApi()
    .on(
      '/nodegroups/{id}',
      nodeGroupDetail({
        agentData: false,
        group: { ...nodeGroupDetail().group, id: 'worker-pool-a-nodeinfo', kind: 'nodeinfo' },
        members: [
          member('worker-1', pending('host inventory quarantined until 2026-11-21T07:10:00Z: scan failed', 'scan failed: disk full')),
          member('worker-2', pending('no full host report received')),
          member('worker-3', pending('host packages not inventoried yet')),
        ],
      }),
    )
    .on('/findings', findingsPage())
  const { user } = renderApp('/nodegroups/worker-pool-a-nodeinfo')
  const main = await screen.findByRole('main')
  // Under the header, and in place of the findings.
  await waitFor(() => expect(within(main).getAllByText(copy.nodes.hostPending)).toHaveLength(2))
  for (const m of within(main).getAllByText(copy.nodes.hostPending)) expect(m.closest('.hatched')).not.toBeNull()
  expect(within(main).getAllByText('3 of 3 nodes')).toHaveLength(2)
  // The server's ordered detail (a quarantine and when it lifts) first; a detail that only repeats
  // the headline is not a reason.
  const reasons = 'host inventory quarantined until 2026-11-21T07:10:00Z: scan failed · no full host report received'
  expect(within(main).getByText(reasons)).toBeInTheDocument()
  expect(within(main).queryByText(/Enable the node agent/)).toBeNull()
  expect(within(main).queryByText(copy.gaps.host_not_inventoried.gap)).toBeNull()
  expect(within(main).queryByText(copy.empty)).toBeNull()
  for (const tab of ['Host packages', 'Cached images']) {
    await user.click(screen.getByRole('tab', { name: tab }))
    expect(await within(main).findByText(reasons)).toBeInTheDocument()
    expect(within(main).queryByText(/Enable the node agent/)).toBeNull()
  }
})

test('a node whose agent reports without a host inventory says so with its last error, once', async () => {
  mockApi().on(
    '/nodes/{name}',
    nodeDetail({
      agent: agentStatus({ gaps: [{ code: 'host_not_inventoried', detail: 'scan failed: disk full' }], lastError: 'scan failed: disk full' }),
      group: { id: 'worker-pool-a-nodeinfo', label: 'worker pool', kind: 'nodeinfo' },
    }),
  )
  renderApp('/nodes/worker-1')
  expect((await screen.findByText(copy.nodes.hostPending)).closest('.hatched')).not.toBeNull()
  expect(screen.getAllByText('scan failed: disk full')).toHaveLength(1)
  expect(screen.queryByText(/Enable the node agent/)).toBeNull()
  expect(screen.getByRole('link', { name: 'worker pool' })).toHaveAttribute('href', '/nodegroups/worker-pool-a-nodeinfo')
})

test('the nodes page says a nodeinfo group whose agents report has not inventoried its hosts yet', async () => {
  mockApi().on(
    '/nodegroups',
    nodeGroupsList({
      groups: [
        nodeGroupRow({
          id: 'ubuntu-24.04-k6.8-nodeinfo',
          kind: 'nodeinfo',
          label: 'ubuntu a',
          agents: { reporting: 0, reportingWithoutInventory: 2, stale: 0, never: 0, disabled: 0, unsupported: 0 },
          gaps: ['host_not_inventoried'],
        }),
        nodeGroupRow({
          id: 'talos-1.11-nodeinfo',
          kind: 'nodeinfo',
          label: 'talos b',
          agents: { reporting: 0, reportingWithoutInventory: 0, stale: 0, never: 2, disabled: 0, unsupported: 0 },
          gaps: ['node_agent_missing'],
        }),
      ],
    }),
  )
  renderApp('/nodes')
  const dashes = async (name: string) => within(await screen.findByRole('row', { name: new RegExp(name) })).getAllByText('—')
  for (const d of await dashes('ubuntu a')) expect(d).toHaveAttribute('title', copy.nodes.hostPending)
  for (const d of await dashes('talos b')) expect(d).toHaveAttribute('title', copy.gaps.node_agent_missing.gap)
  expect(within(await screen.findByRole('row', { name: /ubuntu a/ })).getByText('2 without host inventory')).toBeInTheDocument()
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
          nodeGroupRow({
            id: 'g3',
            name: 'debian-13-k6.12',
            label: 'debian c',
            agents: { reporting: 1, reportingWithoutInventory: 0, stale: 1, never: 0, disabled: 0, unsupported: 0 },
            gaps: ['node_agent_missing'],
          }),
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

test.each([
  ['node_agent_blocked', true],
  ['no_package_database', true],
  ['node_agent_missing', true],
  ['host_not_inventoried', true],
  ['node_agent_unsupported', true],
  ['content_store_unreadable', false],
] as const)('the nodes page hatches a group by its own gaps, beyond the rail: %s', async (code, hatched) => {
  mockApi()
    .on('/nodegroups', nodeGroupsList({ groups: [nodeGroupRow({ id: 'ubuntu-24.04-k6.8', label: 'ubuntu a', gaps: [code] })] }))
    .on('/scope', scopeCard({ related: [{ id: 'nodegroups', more: 0, items: [] }] }))
  renderApp('/nodes')
  const row = await screen.findByRole('row', { name: /ubuntu a/ })
  expect(row.querySelectorAll('.hatched')).toHaveLength(hatched ? 3 : 0)
})

test('the nodes page counts agents by state and leaves zero states out', async () => {
  mockApi().on(
    '/nodegroups',
    nodeGroupsList({
      groups: [
        nodeGroupRow({
          id: 'ubuntu-24.04-k6.8',
          label: 'ubuntu a',
          members: 9,
          agents: { reporting: 7, reportingWithoutInventory: 1, stale: 0, never: 0, disabled: 0, unsupported: 1 },
          gaps: ['host_not_inventoried', 'node_agent_unsupported'],
        }),
        nodeGroupRow({
          id: 'rocky-9-k5.14',
          label: 'rocky b',
          members: 3,
          agents: { reporting: 0, reportingWithoutInventory: 0, stale: 1, never: 1, disabled: 1, unsupported: 0 },
          gaps: ['node_agent_missing'],
        }),
        nodeGroupRow({ id: 'debian-13-k6.12', label: 'debian c', members: 2 }),
      ],
    }),
  )
  renderApp('/nodes')
  const agentsCell = async (name: string) => {
    const row = await screen.findByRole('row', { name: new RegExp(name) })
    const col = screen.getAllByRole('columnheader').findIndex((h) => h.textContent === 'Agents')
    return within(row).getAllByRole('cell')[col]
  }
  expect(await agentsCell('ubuntu a')).toHaveTextContent(/^7 reporting · 1 without host inventory · 1 not scheduled$/)
  expect(await agentsCell('rocky b')).toHaveTextContent(/^1 stale · 1 never reported · 1 disabled$/)
  expect(await agentsCell('debian c')).toHaveTextContent(/^2 reporting$/)
})

test('a node group key is used as it is in its link, its page request and its scope', async () => {
  const key = 'ubuntu-24.04-k6.8@worker-1'
  const api = mockApi()
    .on('/nodegroups', nodeGroupsList({ groups: [nodeGroupRow({ id: key, label: 'ubuntu a' })] }))
    .on('/nodegroups/{id}', nodeGroupDetail({ agentData: true, group: { ...nodeGroupDetail().group, id: key, label: 'ubuntu a' } }))
    .on('/findings', findingsPage())
  const { router, user } = renderApp('/nodes')
  const link = await screen.findByRole('link', { name: /ubuntu a/ })
  expect(link).toHaveAttribute('href', '/nodegroups/ubuntu-24.04-k6.8%40worker-1')
  await user.click(link)
  await waitFor(() => expect(api.calls('/findings').length).toBeGreaterThan(0))
  expect(router.state.location.pathname).toBe('/nodegroups/ubuntu-24.04-k6.8%40worker-1')
  expect(api.calls('/nodegroups/{id}')[0].pathname).toBe('/api/v1/nodegroups/ubuntu-24.04-k6.8%40worker-1')
  // The scope goes out query-encoded and comes back whole.
  const findings = api.calls('/findings')[0]
  expect(findings.searchParams.get('scope')).toBe(`nodegroup:${key}`)
  expect(findings.search).toContain('%40')
  expect(api.calls('/scope').some((u) => u.searchParams.get('scope') === `nodegroup:${key}`)).toBe(true)
})

test('an explorer scoped to a node that no longer exists hands over to /nodes with a notice', async () => {
  mockApi().on('/findings', problem(404, 'not_found', 'node worker-9 not found')).on('/nodegroups', nodeGroupsList())
  const { router } = renderApp('/vulnerabilities?scope=node:worker-9')
  await waitFor(() => expect(router.state.location.pathname).toBe('/nodes'))
  expect(router.state.location.search).toEqual({})
  expect(await screen.findByRole('status')).toHaveTextContent('That node no longer exists.')
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

test('the control plane shows each version with its lifecycle, the note when there is no end-of-life date', async () => {
  const eol = { eolDate: '', isEol: false, latest: '', note: '', text: '' }
  mockApi()
    .on(
      '/nodegroups',
      nodeGroupsList({
        controlPlane: {
          kubernetes: [{ version: '1.35.1', nodes: 3, eol: { ...eol, product: 'kubernetes', cycle: '1.35', eolDate: '2027-02-28', text: 'Kubernetes 1.35 supported until 2027-02-28' } }],
          runtimes: [
            { name: 'containerd', version: '2.1.4', nodes: 2, eol: { ...eol, product: 'containerd', cycle: '2.1', note: 'supported while 2.1 is the latest minor release' } },
            { name: 'cri-o', version: '1.35.0', nodes: 1, eol: { ...eol, product: 'cri-o', cycle: '1.35', note: 'rolling release', text: 'CRI-O 1.35: rolling release' } },
          ],
          counts: counts(),
          fixable: 0,
          suggestions: [],
        },
      }),
    )
    .on('/findings', findingsPage())
  renderApp('/controlplane')
  expect(await screen.findByText('Kubernetes 1.35 supported until 2027-02-28')).toBeInTheDocument()
  expect(screen.getByText('supported while 2.1 is the latest minor release')).toBeInTheDocument()
  expect(screen.getByText('CRI-O 1.35: rolling release')).toBeInTheDocument()
})

test.each([
  ['its text', { note: 'rolling release', text: 'Talos Linux 1.9: rolling release' }, 'Talos Linux 1.9: rolling release'],
  ['its note without text', { note: 'security updates for the two latest minor releases', text: '' }, 'security updates for the two latest minor releases'],
])('a node page shows the OS lifecycle by %s', async (_, e, want) => {
  const n = nodeDetail().node
  mockApi().on(
    '/nodes/{name}',
    nodeDetail({ node: { ...n, osImage: 'Talos (v1.9.5)', osEol: { product: 'talos', cycle: '1.9', eolDate: '', isEol: false, latest: '', ...e } } }),
  )
  renderApp('/nodes/worker-1')
  expect(await screen.findByText(want)).toBeInTheDocument()
})
