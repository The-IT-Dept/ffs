import type { ReactNode } from 'react'

// CoverageMark is the one treatment for what ffs cannot see: hatched and dashed, never a colour.
export function CoverageMark({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span title={title} className="hatched inline-block rounded-sm px-1">
      {children}
    </span>
  )
}
