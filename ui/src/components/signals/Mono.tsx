import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

// Mono is for IDs, digests and versions only. It truncates, unless wrap lets a long value (a digest
// or an image reference in a page header) break anywhere instead.
export function Mono({ children, title, className, wrap }: { children: ReactNode; title?: string; className?: string; wrap?: boolean }) {
  return (
    <span title={title} className={cn(wrap ? 'font-mono text-[11px] wrap-anywhere' : 'truncate font-mono text-[11px]', className)}>
      {children}
    </span>
  )
}
