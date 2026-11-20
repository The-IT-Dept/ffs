import { ArrowDown, ArrowUp } from 'lucide-react'
import type { ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { cn } from '@/lib/utils'

export interface Column<R> {
  id: string
  header: string
  cell: (row: R) => ReactNode
  sort?: string // the sort value this column's header asks the server for
  align?: 'right'
}

function sortDirection(sort: string): 'descending' | 'ascending' {
  return sort.startsWith('-') ? 'descending' : 'ascending'
}

// ExplorerTable is a dense table of server rows: 30 px rows, tabular numbers, and sortable
// headers that ask the server to sort. It never sorts or filters rows itself. Below the lg
// breakpoint rows and sort buttons are 40 px tall, for touch (spec §12); the 30 px rows of §5 are
// the desktop density.
export function ExplorerTable<R>({
  columns,
  rows,
  rowKey,
  sort,
  onSort,
  busy,
}: {
  columns: Column<R>[]
  rows: R[]
  rowKey: (r: R) => string
  sort?: string
  onSort?: (sort: string) => void
  busy?: boolean
}) {
  return (
    <Table className="text-[12px]">
      <TableHeader>
        <TableRow className="h-[30px] hover:bg-transparent max-lg:h-10">
          {columns.map((c) => {
            const active = c.sort !== undefined && c.sort === sort
            const Icon = active ? (sortDirection(c.sort!) === 'descending' ? ArrowDown : ArrowUp) : null
            return (
              <TableHead
                key={c.id}
                aria-sort={active ? sortDirection(c.sort!) : undefined}
                className={cn('h-[30px] py-0 text-[11px] font-medium text-muted-foreground max-lg:h-10', c.align === 'right' && 'text-right')}
              >
                {c.sort && onSort ? (
                  <Button
                    variant="ghost"
                    size="xs"
                    className={cn('-mx-2 h-6 px-2 text-[11px] font-medium max-lg:h-10', active ? 'text-foreground' : 'text-muted-foreground')}
                    onClick={() => onSort(c.sort!)}
                  >
                    {c.header}
                    {Icon ? <Icon aria-hidden="true" /> : null}
                  </Button>
                ) : (
                  c.header
                )}
              </TableHead>
            )
          })}
        </TableRow>
      </TableHeader>
      <TableBody className={cn(busy && 'opacity-60')}>
        {rows.map((r) => (
          <TableRow key={rowKey(r)} className="h-[30px] max-lg:h-10">
            {columns.map((c, i) => (
              <TableCell key={c.id} className={cn('max-w-[28rem] truncate py-0 tabular-nums', i === 0 && 'max-lg:max-w-(--pin-max)', c.align === 'right' && 'text-right')}>
                {c.cell(r)}
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
