import type { ReactNode } from 'react'
import { CommandMenu } from '@/components/command/CommandMenu'
import { Rail } from '@/components/rail/Rail'
import { AppLink } from './AppLink'
import { ThemeToggle } from './ThemeToggle'

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-screen flex-col bg-background text-foreground">
      <header className="flex h-11 shrink-0 items-center gap-3 border-b px-4">
        <AppLink href="/" className="text-[15px] font-semibold tracking-tight">
          ffs
        </AppLink>
        <div className="ml-auto flex items-center gap-2">
          <CommandMenu />
          <ThemeToggle />
        </div>
      </header>
      <div className="flex min-h-0 flex-1">
        <aside aria-label="Scope" className="w-[200px] shrink-0 overflow-y-auto border-r bg-muted/40">
          <Rail />
        </aside>
        <main className="min-w-0 flex-1 overflow-y-auto px-6 py-4">{children}</main>
      </div>
    </div>
  )
}
