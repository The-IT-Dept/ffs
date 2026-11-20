import { formatCount } from '@/lib/format'
import { cn } from '@/lib/utils'
import { priorityTone } from './tone'

// PriorityCount is red (urgent) or orange (high) only when above zero.
export function PriorityCount({ priority, n }: { priority: 'urgent' | 'high'; n: number }) {
  return <span className={cn('tabular-nums', n > 0 ? [priorityTone[priority].text, 'font-semibold'] : 'text-muted-foreground')}>{formatCount(n)}</span>
}
