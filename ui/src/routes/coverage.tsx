import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import { apiQuery } from '@/api/client'
import { Funnel } from '@/components/coverage/Funnel'
import { GapsTable } from '@/components/coverage/GapsTable'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { Skeleton } from '@/components/ui/skeleton'
import { copy } from '@/lib/copy'
import { parseCoverageSearch, revalidate } from '@/lib/query'
import { parseScope, scopeParam } from '@/lib/scope'
import { rootRoute } from './root'

function CoveragePage() {
  const search = revalidate(parseCoverageSearch, coverageRoute.useSearch())
  const q = useQuery(apiQuery('/coverage', { query: scopeParam(parseScope(search.scope)) }))
  return (
    <div>
      <PageHeader title={copy.page.coverage} />
      {q.data ? (
        <>
          <Funnel funnel={q.data.funnel} />
          <GapsTable gaps={q.data.gaps} totalGaps={q.data.totalGaps} />
        </>
      ) : q.error ? (
        <ProblemNotice error={q.error} />
      ) : (
        <Skeleton className="h-40" />
      )}
    </div>
  )
}

export const coverageRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/coverage',
  validateSearch: parseCoverageSearch,
  component: CoveragePage,
})
