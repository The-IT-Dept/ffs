import { useQuery } from '@tanstack/react-query'
import { createLazyRoute } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { apiQuery } from '@/api/client'
import { FixGroupFindings } from '@/components/fix/FixGroupFindings'
import { EmptyState, useScopeTrust } from '@/components/layout/EmptyState'
import { UpgradeTable } from '@/components/fix/UpgradeTable'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { ControlPlaneBlock } from '@/components/nodes/ControlPlaneBlock'
import { Skeleton } from '@/components/ui/skeleton'
import { copy } from '@/lib/copy'

const SCOPE = 'controlplane'

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mt-5">
      <h2 className="mb-1.5 text-[10px] font-medium tracking-wider text-muted-foreground uppercase">{title}</h2>
      {children}
    </section>
  )
}

function ControlPlanePage() {
  const list = useQuery(apiQuery('/nodegroups', {}))
  const trust = useScopeTrust({ kind: 'controlplane', value: '' })
  return (
    <div>
      <PageHeader title={copy.page.controlplane} />
      {list.data ? (
        <>
          <ControlPlaneBlock controlPlane={list.data.controlPlane} />
          <Section title={copy.view('upgrades', 'controlplane')}>
            <UpgradeTable suggestions={list.data.controlPlane.suggestions} />
          </Section>
        </>
      ) : list.error ? (
        <ProblemNotice error={list.error} />
      ) : (
        <Skeleton className="h-24" />
      )}
      <Section title={copy.view('findings', 'controlplane')}>
        <FixGroupFindings scope={SCOPE} empty={<EmptyState coverage={trust?.coverage} feeds={trust?.feeds} />} />
      </Section>
    </div>
  )
}

// The page's code loads with its first visit; lazy.ts defines the route.
export const Route = createLazyRoute('/controlplane')({ component: ControlPlanePage })
