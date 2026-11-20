import { XIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { copy } from '@/lib/copy'
import type { Chip } from '@/lib/query'

export function FilterChips({ chips, onRemove, onClear }: { chips: Chip[]; onRemove: (c: Chip) => void; onClear: () => void }) {
  if (chips.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {chips.map((c) => (
        <Badge key={`${c.key}:${c.value}`} variant="outline" className="gap-0.5 pr-0.5 font-normal max-lg:py-0 max-lg:pl-3">
          <span>{c.label}</span>
          <Button
            variant="ghost"
            size="icon-xs"
            className="size-4 rounded-full max-lg:h-10 max-lg:w-8"
            aria-label={`Remove ${c.label}`}
            onClick={() => onRemove(c)}
          >
            <XIcon aria-hidden="true" />
          </Button>
        </Badge>
      ))}
      <Button variant="link" size="xs" className="h-5 px-1 text-[11px] text-muted-foreground max-lg:h-10" onClick={onClear}>
        {copy.explorer.clear}
      </Button>
    </div>
  )
}
