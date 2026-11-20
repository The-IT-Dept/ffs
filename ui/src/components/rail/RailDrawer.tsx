import { useRouterState } from '@tanstack/react-router'
import { MenuIcon } from 'lucide-react'
import { type MouseEvent, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import { copy } from '@/lib/copy'
import { Rail, useRailScope } from './Rail'

// RailDrawer is the rail below the lg breakpoint: a menu button in the top bar, labelled with the
// current scope, opens it as a sheet from the left. Any navigation closes it, and so does a tap on
// any of its links, even one to the page already open.
export function RailDrawer() {
  const { rs, q } = useRailScope()
  const href = useRouterState({ select: (s) => s.location.href })
  const [open, setOpen] = useState(false)
  const [openedAt, setOpenedAt] = useState(href)
  if (openedAt !== href) {
    setOpenedAt(href)
    setOpen(false)
  }

  const kind = copy.scopeKind(rs.scope)
  const name = q.data?.title
  const onLinkClick = (e: MouseEvent) => {
    if (e.target instanceof Element && e.target.closest('a[href]')) setOpen(false)
  }

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button
          variant="ghost"
          aria-label={copy.shell.openNavigation}
          title={name && name !== kind ? `${kind}: ${name}` : kind}
          className="h-10 min-w-0 shrink justify-start gap-1.5 px-2 text-[13px] font-normal"
        >
          <MenuIcon aria-hidden="true" />
          {name !== kind ? <span className="shrink-0 text-muted-foreground">{kind}</span> : null}
          {name ? <span className="min-w-0 truncate font-medium">{name}</span> : null}
        </Button>
      </SheetTrigger>
      <SheetContent
        side="left"
        aria-describedby={undefined}
        closeLabel={copy.shell.close}
        className="w-[280px] max-w-[85vw] gap-0 overflow-y-auto sm:max-w-[85vw]"
        onClickCapture={onLinkClick}
      >
        <SheetTitle className="sr-only">{copy.shell.navigation}</SheetTitle>
        <div className="min-h-full bg-muted/40 pt-11">
          <Rail />
        </div>
      </SheetContent>
    </Sheet>
  )
}
