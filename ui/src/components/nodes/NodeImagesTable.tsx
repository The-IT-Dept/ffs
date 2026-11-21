import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { EmptyState } from '@/components/layout/EmptyState'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy, facetValueLabel } from '@/lib/copy'
import { formatBytes, formatCount, shortDigest } from '@/lib/format'
import { imagePath } from '@/lib/links'
import { cn } from '@/lib/utils'

// NodeImagesTable lists the images a node (or node group) holds in its content store or reports
// in its status. An image ffs has a record of links to its page.
export function NodeImagesTable({ images }: { images: S<'NodeImage'>[] }) {
  if (images.length === 0) return <EmptyState message={copy.emptyList.cachedImages} />
  const c = copy.nodes.imageCols
  const yesNo = (b: boolean) => (b ? copy.nodes.yes : copy.nodes.no)
  const heads = [
    { label: c.image },
    { label: c.size, right: true },
    { label: c.complete },
    { label: c.inUse },
    { label: c.nodes, right: true },
    { label: c.status },
  ]
  return (
    <Table className="text-[12px]">
      <TableHeader>
        <TableRow className="h-[30px] hover:bg-transparent">
          {heads.map((h) => (
            <TableHead key={h.label} className={cn('h-[30px] py-0 text-[11px] font-medium text-muted-foreground', h.right && 'text-right')}>
              {h.label}
            </TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {images.map((im) => {
          const name = <Mono>{im.names[0] ?? shortDigest(im.digest)}</Mono>
          return (
            <TableRow key={im.digest} className="h-[30px]">
              <TableCell className="max-w-[28rem] truncate py-0 max-lg:max-w-(--pin-max)">
                {im.status ? (
                  <AppLink href={imagePath(im.digest)} className="hover:underline">
                    {name}
                  </AppLink>
                ) : (
                  name
                )}
                {im.names.length > 1 ? <span className="ml-1.5 text-muted-foreground">+{formatCount(im.names.length - 1)}</span> : null}
              </TableCell>
              <TableCell className="py-0 text-right tabular-nums">{formatBytes(im.sizeBytes)}</TableCell>
              <TableCell className="py-0">{yesNo(im.complete)}</TableCell>
              <TableCell className="py-0">{yesNo(im.inUse)}</TableCell>
              <TableCell className="py-0 text-right tabular-nums">{formatCount(im.nodes.length)}</TableCell>
              <TableCell className="py-0">
                {im.status === undefined ? (
                  <span className="text-muted-foreground">{copy.noValue}</span>
                ) : im.status === 'catalogued' ? (
                  facetValueLabel('status', im.status)
                ) : (
                  <CoverageMark title={im.statusReason || undefined}>{facetValueLabel('status', im.status)}</CoverageMark>
                )}
              </TableCell>
            </TableRow>
          )
        })}
      </TableBody>
    </Table>
  )
}
