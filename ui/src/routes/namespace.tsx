import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { createRoute, redirect } from '@tanstack/react-router'
import { useState } from 'react'
import { apiQuery } from '@/api/client'
import { ExposureTable } from '@/components/exposure/ExposureTable'
import { Footnote } from '@/components/exposure/Footnote'
import { CoverageFirstLine, EmptyState } from '@/components/layout/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { Skeleton } from '@/components/ui/skeleton'
import { copy } from '@/lib/copy'
import { parseNamespaceSearch, revalidate, toggleExpand } from '@/lib/query'
import { formatScope, type Scope } from '@/lib/scope'
import { rootRoute } from './root'

function NamespaceView({ namespace }: { namespace: string }) {
  const scopeOf: Scope = { kind: 'namespace', value: namespace }
  const scope = formatScope(scopeOf)
  // The namespace route keeps no expand param, so folding is page state here.
  const [expand, setExpand] = useState<string | undefined>()
  const summary = useQuery(apiQuery('/summary', { query: { scope } }))
  const exposure = useQuery({
    ...apiQuery('/exposure', { query: { scope, ...(expand ? { expand: expand.split(',') } : {}) } }),
    placeholderData: keepPreviousData,
  })

  let table
  if (exposure.data) {
    table =
      exposure.data.rows.length === 0 ? (
        <EmptyState coverage={summary.data?.coverage} feeds={summary.data?.feeds} scope={scopeOf} />
      ) : (
        <ExposureTable table={exposure.data} expand={expand} onToggle={(id) => setExpand((e) => toggleExpand(e, id))} />
      )
  } else if (exposure.error) {
    table = <ProblemNotice error={exposure.error} />
  } else {
    table = <Skeleton className="h-40" />
  }

  return (
    <div>
      <PageHeader kind={copy.scopeKind(scopeOf)} title={namespace} />
      <CoverageFirstLine coverage={summary.data?.coverage} scope={scopeOf} className="mb-3 text-[12px] text-muted-foreground" />
      {table}
      <Footnote />
    </div>
  )
}

// Keyed by namespace, so folding state and the previous table never carry over to another one.
function NamespacePage() {
  const { namespace } = namespaceRoute.useParams()
  return <NamespaceView key={namespace} namespace={namespace} />
}

export const namespaceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/namespaces/$namespace',
  validateSearch: parseNamespaceSearch,
  // The namespace's explorer views are the scoped explorers themselves.
  beforeLoad: ({ params, search }) => {
    const { view } = revalidate(parseNamespaceSearch, search)
    if (!view || view === 'exposure') return
    const scoped = { scope: formatScope({ kind: 'namespace', value: params.namespace }) }
    if (view === 'vulnerabilities') throw redirect({ to: '/vulnerabilities', search: scoped, replace: true })
    if (view === 'images') throw redirect({ to: '/images', search: scoped, replace: true })
    throw redirect({ to: '/packages', search: scoped, replace: true })
  },
  component: NamespacePage,
})
