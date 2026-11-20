import { Monitor, Moon, Sun } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { copy } from '@/lib/copy'
import { applyTheme, nextTheme, readTheme, systemQuery, type ThemeChoice } from '@/lib/theme'

// ThemeToggle cycles light, dark and system. While on system it follows the operating system's
// preference as it changes.
export function ThemeToggle() {
  const [choice, setChoice] = useState<ThemeChoice>(readTheme)

  useEffect(() => {
    if (choice !== 'system') return
    const mq = systemQuery()
    if (!mq) return
    const follow = () => document.documentElement.classList.toggle('dark', mq.matches)
    mq.addEventListener('change', follow)
    return () => mq.removeEventListener('change', follow)
  }, [choice])

  const Icon = choice === 'light' ? Sun : choice === 'dark' ? Moon : Monitor
  return (
    <Button
      variant="ghost"
      size="icon-sm"
      aria-label={`Theme: ${copy.theme[choice]}`}
      title={`Theme: ${copy.theme[choice]}`}
      onClick={() => {
        const next = nextTheme(choice)
        applyTheme(next)
        setChoice(next)
      }}
    >
      <Icon aria-hidden="true" />
    </Button>
  )
}
