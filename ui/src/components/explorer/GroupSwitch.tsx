import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'

// Radix treats an empty toggle value as "nothing selected", so option values travel prefixed.
const encode = (v: string) => `v:${v}`

// GroupSwitch is a single-choice switch; choosing the current option again changes nothing.
export function GroupSwitch({
  value,
  options,
  onChange,
  label,
}: {
  value: string
  options: readonly { value: string; label: string }[]
  onChange: (v: string) => void
  label?: string
}) {
  return (
    <div className="flex items-center gap-2">
      {label ? <span className="text-[11px] text-muted-foreground">{label}</span> : null}
      <ToggleGroup
        type="single"
        variant="outline"
        size="sm"
        aria-label={label}
        value={encode(value)}
        onValueChange={(raw) => {
          if (!raw) return
          const next = raw.slice(2)
          if (next !== value) onChange(next)
        }}
      >
        {options.map((o) => (
          <ToggleGroupItem key={o.value} value={encode(o.value)} className="h-7 px-2.5 text-[12px]">
            {o.label}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
    </div>
  )
}
