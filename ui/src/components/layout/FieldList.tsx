import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

// FieldList is a page's label and value list: a 10rem label column (7rem on a phone) and values
// that break anywhere rather than widen the page. className can add text size or row spacing.
export function FieldList({ className, children }: { className?: string; children: ReactNode }) {
  return <dl className={cn('grid max-w-2xl grid-cols-[10rem_minmax(0,1fr)] gap-x-4 gap-y-1.5 wrap-anywhere max-sm:grid-cols-[7rem_minmax(0,1fr)]', className)}>{children}</dl>
}

// Field is one label and its value in a FieldList.
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd>{children}</dd>
    </>
  )
}
