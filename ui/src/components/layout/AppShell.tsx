import type { ReactNode } from 'react'
import { CommandMenu } from '@/components/command/CommandMenu'
import { Rail } from '@/components/rail/Rail'
import { RailDrawer } from '@/components/rail/RailDrawer'
import { useMediaQuery, WIDE } from '@/lib/hooks'
import { AppLink } from './AppLink'
import { GoneNotice } from './GoneNotice'
import { ThemeToggle } from './ThemeToggle'

// AppShell is the top bar, the rail and the page. From the lg breakpoint the rail sits inline and
// the page scrolls inside its own column; below it the rail is a drawer behind a menu button and
// the document scrolls, under a sticky top bar.
export function AppShell({ children }: { children: ReactNode }) {
  const wide = useMediaQuery(WIDE)
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground lg:h-screen">
      <header className="sticky top-0 z-40 flex h-11 shrink-0 items-center gap-3 border-b bg-background px-4 lg:static">
        <AppLink href="/" className="shrink-0 text-[15px] font-semibold tracking-tight max-lg:inline-flex max-lg:h-10 max-lg:items-center">
          ffs
        </AppLink>
        {wide ? null : <RailDrawer />}
        <div className="ml-auto flex shrink-0 items-center gap-2">
          <CommandMenu compact={!wide} />
          <ThemeToggle />
        </div>
      </header>
      <div className="flex min-h-0 flex-1">
        {wide ? (
          <aside aria-label="Scope" className="w-[200px] shrink-0 overflow-y-auto border-r bg-muted/40">
            <Rail />
          </aside>
        ) : null}
        <main className="min-w-0 flex-1 px-4 py-4 sm:px-6 lg:overflow-y-auto">
          <GoneNotice />
          {children}
        </main>
      </div>
    </div>
  )
}
