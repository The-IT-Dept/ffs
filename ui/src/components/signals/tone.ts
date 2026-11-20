import type { Priority } from '@/api/types'

// Colour is spent only on urgent (red), high (orange) and medium dots (amber); the rest is grey.
export const priorityTone: Record<Priority, { text: string; dot: string }> = {
  urgent: { text: 'text-(--urgent)', dot: 'bg-(--urgent)' },
  high: { text: 'text-(--high-text)', dot: 'bg-(--high)' },
  medium: { text: 'text-muted-foreground', dot: 'bg-(--medium)' },
  low: { text: 'text-muted-foreground', dot: 'bg-zinc-300 dark:bg-zinc-600' },
  none: { text: 'text-muted-foreground', dot: 'bg-zinc-200 dark:bg-zinc-700' },
}
