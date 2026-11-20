import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

// Mono is for IDs, digests and versions only.
export function Mono({ children, title, className }: { children: ReactNode; title?: string; className?: string }) {
  return (
    <span title={title} className={cn('truncate font-mono text-[11px]', className)}>
      {children}
    </span>
  )
}
