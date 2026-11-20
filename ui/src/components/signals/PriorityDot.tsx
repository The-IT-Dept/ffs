import type { Priority } from '@/api/types'
import { cn } from '@/lib/utils'
import { priorityTone } from './tone'

// PriorityDot is a 7 px dot in the priority's tone; a coverage gap is hatched instead of coloured.
export function PriorityDot({ priority, gap }: { priority: Priority; gap?: boolean }) {
  if (gap) {
    return <span role="img" aria-label="coverage gap" className="hatched inline-block size-[7px] shrink-0 rounded-full border border-dashed" />
  }
  return <span role="img" aria-label={priority} className={cn('inline-block size-[7px] shrink-0 rounded-full', priorityTone[priority].dot)} />
}
