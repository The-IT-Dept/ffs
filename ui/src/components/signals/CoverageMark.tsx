import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

// CoverageMark is the one treatment for what ffs cannot see: hatched and dashed, never a colour.
// className sets the ground under the hatching, e.g. on a selected row whose colours are inverted.
export function CoverageMark({ children, title, className }: { children: ReactNode; title?: string; className?: string }) {
  return (
    <span title={title} className={cn('hatched inline-block rounded-sm px-1', className)}>
      {children}
    </span>
  )
}
