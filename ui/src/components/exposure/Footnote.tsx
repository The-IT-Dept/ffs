import { copy } from '@/lib/copy'

// Footnote states exactly what "reachable" means, under every exposure table.
export function Footnote() {
  return <p className="mt-3 max-w-3xl text-[11px] leading-relaxed text-muted-foreground">{copy.footnote}</p>
}
