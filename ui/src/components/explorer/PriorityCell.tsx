import type { S } from '@/api/types'
import { PriorityDot } from '@/components/signals/PriorityDot'
import { priorityTone } from '@/components/signals/tone'
import { copy } from '@/lib/copy'
import { cn } from '@/lib/utils'

function Tag({ children }: { children: string }) {
  return <span className="rounded border px-1 text-[10px] leading-4 text-muted-foreground">{children}</span>
}

// PriorityCell is a finding's priority with why it has it (in the title), plus the muted marks for
// provisional, not-running and excepted findings, which the default view includes and marks.
export function PriorityCell({ finding }: { finding: S<'FindingRow'> }) {
  return (
    <span className="inline-flex items-center gap-1.5" title={finding.reasons.join(' · ') || undefined}>
      <PriorityDot priority={finding.priority} />
      <span className={cn(priorityTone[finding.priority].text, (finding.priority === 'urgent' || finding.priority === 'high') && 'font-medium')}>
        {finding.priority}
      </span>
      {finding.signals.includes('provisional') ? <Tag>{copy.explorer.tag.provisional}</Tag> : null}
      {finding.signals.includes('not_running') ? <Tag>{copy.explorer.tag.notRunning}</Tag> : null}
      {finding.state === 'excepted' ? <Tag>{copy.explorer.tag.excepted}</Tag> : null}
    </span>
  )
}
