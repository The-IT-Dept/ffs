import type { S } from '@/api/types'
import { eolText, eolWarns } from '@/lib/format'

// EolText is a lifecycle status's text (eolText): in the warning tone once end of life has passed or
// is within 90 days (eolWarns), else in className's. Since every status now has text, the tone, not
// the line's presence, is what marks an end of life. It renders nothing when there is no text.
export function EolText({ eol, className }: { eol?: S<'EOL'>; className?: string }) {
  const text = eolText(eol)
  if (!text) return null
  return <span className={eolWarns(eol) ? 'text-(--high-text)' : className}>{text}</span>
}
