import { Fragment } from 'react'
import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { SignalCells } from '@/components/signals/SignalCells'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { scopePath, workloadPath } from '@/lib/links'
import { parseScope } from '@/lib/scope'
import { cn } from '@/lib/utils'

type Row = S<'ExposureRow'>

const headers = [
  { label: copy.columns.path, right: false },
  { label: copy.columns.urgent, right: true },
  { label: copy.columns.high, right: true },
  { label: copy.columns.fixable, right: true },
  { label: copy.columns.privileged, right: true },
  { label: copy.columns.saPower, right: true },
  { label: copy.columns.exploited, right: true },
  { label: copy.columns.coverage, right: true },
  { label: copy.columns.bestFix, right: false },
]

function targetHref(row: Row): string | undefined {
  if (!row.target) return undefined
  try {
    return scopePath(parseScope(row.target.scope))
  } catch {
    return undefined
  }
}

function Label({ row }: { row: Row }) {
  const href = targetHref(row)
  return href ? (
    <AppLink href={href} className="hover:underline">
      {row.label}
    </AppLink>
  ) : (
    <span>{row.label}</span>
  )
}

function Detail({ text }: { text?: string }) {
  return text ? <span className="ml-2 font-normal text-muted-foreground">{text}</span> : null
}

function Hostname({ row }: { row: Row }) {
  const first = row.workloads[0]
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <span>{row.label}</span>
      {row.workloads.length > 0 ? <span aria-hidden="true" className="text-muted-foreground">→</span> : null}
      {row.workloads.map((w, i) => (
        <Fragment key={w.scope}>
          {i > 0 ? <span className="text-muted-foreground">,</span> : null}
          <AppLink href={workloadPath(w.kind, w.namespace, w.name)} className="hover:underline">
            {w.name}
          </AppLink>
        </Fragment>
      ))}
      {row.moreWorkloads > 0 ? <span className="text-muted-foreground">+{formatCount(row.moreWorkloads)}</span> : null}
      {first?.namespace ? <span className="text-muted-foreground">· {first.namespace}</span> : null}
    </span>
  )
}

function GroupPath({ row, open, onToggle }: { row: Row; open: boolean; onToggle: (id: string) => void }) {
  const toggle = row.collapsed ? 'closed' : row.expandable && open ? 'open' : undefined
  if (!toggle) {
    return (
      <span className="inline-flex items-center">
        <Label row={row} />
        <Detail text={row.detail} />
      </span>
    )
  }
  const glyph = toggle === 'open' ? '▾' : '▸'
  const href = targetHref(row)
  // A toggle never wraps a link: a group with a page gets a glyph-only toggle beside its link.
  return (
    <span className="inline-flex items-center">
      {href ? (
        <>
          <button type="button" aria-expanded={toggle === 'open'} aria-label={row.label} className="mr-1 w-3 text-muted-foreground" onClick={() => onToggle(row.id)}>
            {glyph}
          </button>
          <Label row={row} />
        </>
      ) : (
        <button type="button" aria-expanded={toggle === 'open'} className="inline-flex items-center gap-1 font-semibold" onClick={() => onToggle(row.id)}>
          <span aria-hidden="true" className="w-3 text-muted-foreground">
            {glyph}
          </span>
          <span>{row.label}</span>
        </button>
      )}
      <Detail text={row.detail} />
    </span>
  )
}

function ChildPath({ row, last, onToggle }: { row: Row; last: boolean; onToggle: (id: string) => void }) {
  let body
  if (row.kind === 'tail') {
    body = (
      <>
        <button type="button" className="text-muted-foreground hover:text-foreground hover:underline" onClick={() => row.parent && onToggle(row.parent)}>
          {row.label}
        </button>
        <Detail text={row.detail} />
      </>
    )
  } else if (row.kind === 'hostname') {
    body = <Hostname row={row} />
  } else {
    body = (
      <>
        <Label row={row} />
        <Detail text={row.detail} />
      </>
    )
  }
  return (
    <span className="inline-flex items-center pl-3">
      <span aria-hidden="true" className="mr-1.5 text-muted-foreground">
        {last ? '└' : '├'}
      </span>
      {body}
    </span>
  )
}

// ExposureTable is the home and namespace table: the exposure path on the left, the signal columns
// on the right, rows in the server's order. Folding and expanding go through onToggle, which
// writes the expand list the server folds by.
export function ExposureTable({ table, expand, onToggle }: { table: S<'ExposureTable'>; expand?: string; onToggle: (id: string) => void }) {
  const open = new Set((expand ?? '').split(',').filter((x) => x !== ''))
  return (
    <Table className="text-[12px]">
      <TableHeader>
        <TableRow className="h-[30px] hover:bg-transparent">
          {headers.map((h) => (
            <TableHead key={h.label} className={cn('h-[30px] py-0 text-[11px] font-medium text-muted-foreground', h.right && 'text-right')}>
              {h.label}
            </TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {table.rows.map((row, i) => {
          const next = table.rows[i + 1]
          return (
            <TableRow key={row.id} data-tinted={row.depth === 0 ? '' : undefined} className={cn('h-[30px]', row.depth === 0 && 'bg-muted/50 font-semibold')}>
              <TableCell className="max-w-[34rem] truncate py-0">
                {row.depth === 0 ? (
                  <GroupPath row={row} open={open.has(row.id)} onToggle={onToggle} />
                ) : (
                  <ChildPath row={row} last={!next || next.parent !== row.parent} onToggle={onToggle} />
                )}
              </TableCell>
              <SignalCells signals={row.signals} max={table.maxUrgent} />
            </TableRow>
          )
        })}
      </TableBody>
    </Table>
  )
}
