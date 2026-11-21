import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { copy, facetValueLabel } from '@/lib/copy'
import { eolText } from '@/lib/format'
import { ownerHref, ownerLabel } from '@/lib/links'
import { cn, touchLink } from '@/lib/utils'
import { EcosystemBreakdown } from './EcosystemBreakdown'

function Heading({ children }: { children: string }) {
  return <h2 className="mt-4 mb-1 text-[10px] font-medium tracking-wider text-muted-foreground uppercase">{children}</h2>
}

function Gap({ label, todo }: { label: string; todo?: string }) {
  return (
    <li className="flex flex-wrap items-baseline gap-2">
      <CoverageMark>{label}</CoverageMark>
      {todo ? <span className="text-muted-foreground">{todo}</span> : null}
    </li>
  )
}

// hasImageGaps reports whether ImageGaps has anything to list for an image.
export function hasImageGaps(image: S<'ImageDetail'>): boolean {
  const c = image.coverage
  return c.unattributedExecutables > 0 || c.rustWithoutAuditable > 0 || c.gaps.length > 0 || c.cpeOnly.length > 0
}

// ImageGaps lists what ffs cannot see in an image, hatched, with what to do about each gap.
export function ImageGaps({ image, className }: { image: S<'ImageDetail'>; className?: string }) {
  const { coverage } = image
  const cpe = coverage.cpeOnly.join(', ')
  return (
    <ul className={cn('flex flex-col gap-1', className)}>
      {coverage.unattributedExecutables > 0 ? <Gap label={copy.image.unattributed(coverage.unattributedExecutables)} /> : null}
      {coverage.rustWithoutAuditable > 0 ? <Gap label={copy.image.rust(coverage.rustWithoutAuditable)} /> : null}
      {coverage.gaps.map((g) => (
        <Gap key={g} label={copy.gaps[g].gap} todo={copy.gaps[g].todo.replace('{names}', cpe)} />
      ))}
      {coverage.cpeOnly.length > 0 && !coverage.gaps.includes('cpe_only_classifier') ? <Gap label={`${copy.gaps.cpe_only_classifier.gap}: ${cpe}`} /> : null}
    </ul>
  )
}

// SbomCard is where an image's package list came from and what it cannot see: the SBOM source,
// coverage gaps (hatched), notes, the ecosystem breakdown, lifecycle and the workloads using it.
export function SbomCard({ image }: { image: S<'ImageDetail'> }) {
  const { sbom, coverage } = image
  return (
    <div className="max-w-3xl text-[12px]">
      <p>{copy.image.sbom(sbom.source, sbom.tool, sbom.toolVersion)}</p>
      {sbom.agent ? (
        <p className="text-muted-foreground">
          {copy.image.agent(sbom.agent.node, sbom.agent.agentVersion)} · <RelativeTime iso={sbom.agent.receivedAt} />
        </p>
      ) : null}
      <p className="mt-1">{copy.workload.coverage(facetValueLabel('coverage', coverage.class))}</p>
      <ImageGaps image={image} className="mt-2" />
      {coverage.notes.length > 0 ? (
        <ul className="mt-2 list-disc pl-4 text-muted-foreground">
          {coverage.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      ) : null}
      {image.ecosystems.length > 0 ? (
        <>
          <Heading>{copy.image.ecosystems}</Heading>
          <EcosystemBreakdown ecosystems={image.ecosystems} />
        </>
      ) : null}
      {image.eol.length > 0 ? (
        <>
          <Heading>{copy.image.lifecycle}</Heading>
          {image.eol.map((e) => (
            <p key={`${e.product}:${e.cycle}`}>{eolText(e)}</p>
          ))}
        </>
      ) : null}
      {image.usedBy.length > 0 ? (
        <>
          <Heading>{copy.image.usedBy}</Heading>
          <ul className="flex flex-wrap gap-x-3 gap-y-1">
            {image.usedBy.map((w) => (
              <li key={w.scope}>
                <AppLink href={ownerHref(w)} className={cn('hover:underline', touchLink)}>
                  {ownerLabel(w)}
                </AppLink>{' '}
                <span className="text-muted-foreground">{w.namespace}</span>
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  )
}
