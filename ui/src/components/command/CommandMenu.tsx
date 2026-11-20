import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { SearchIcon, XIcon } from 'lucide-react'
import { useEffect, useState } from 'react'
import { apiQuery } from '@/api/client'
import { PriorityDot } from '@/components/signals/PriorityDot'
import { Button } from '@/components/ui/button'
import { Command, CommandEmpty, CommandInput, CommandItem, CommandList } from '@/components/ui/command'
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { copy } from '@/lib/copy'
import { useDebounced } from '@/lib/hooks'
import { hitPath } from '@/lib/links'

export const SEARCH_DEBOUNCE_MS = 150

// isApple reports whether the browser runs on macOS or iOS, where the shortcut is ⌘K; elsewhere
// it is Ctrl K. Both work everywhere.
export function isApple(): boolean {
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } }
  return /mac|iphone|ipad|ipod/i.test(nav.userAgentData?.platform || nav.platform || '')
}

// CommandMenu is ⌘K / Ctrl-K: a jump to any object, searched on the server. It composes Dialog and
// Command itself because shadcn's CommandDialog cannot turn off cmdk's client-side filtering. On a
// narrow screen (compact) it opens from a search icon instead, and below sm the dialog fills the
// screen, with its own close button.
export function CommandMenu({ compact = false }: { compact?: boolean }) {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  const term = useDebounced(input.trim().slice(0, 100), SEARCH_DEBOUNCE_MS)
  const search = useQuery({ ...apiQuery('/search', { query: { q: term } }), enabled: term.length > 0 })
  const hits = term.length > 0 ? (search.data?.hits ?? []) : []

  const setOpenAndReset = (o: boolean) => {
    setOpen(o)
    if (!o) setInput('')
  }

  return (
    <>
      {compact ? (
        <Button variant="ghost" size="icon" className="size-10" aria-label={copy.command.open} title={copy.command.open} onClick={() => setOpen(true)}>
          <SearchIcon aria-hidden="true" />
        </Button>
      ) : (
        <Button variant="outline" size="sm" className="h-7 gap-2 px-2 text-[12px] font-normal text-muted-foreground" onClick={() => setOpen(true)}>
          <SearchIcon aria-hidden="true" />
          <span>{copy.command.open}</span>
          <kbd className="rounded border bg-muted px-1 font-sans text-[10px]">{copy.command.shortcut(isApple())}</kbd>
        </Button>
      )}
      <Dialog open={open} onOpenChange={setOpenAndReset}>
        <DialogContent
          className="overflow-hidden p-0 max-sm:top-0 max-sm:left-0 max-sm:flex max-sm:h-dvh max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:flex-col max-sm:rounded-none max-sm:border-0"
          showCloseButton={false}
        >
          <DialogTitle className="sr-only">{copy.command.open}</DialogTitle>
          <DialogDescription className="sr-only">{copy.command.placeholder}</DialogDescription>
          <Command
            shouldFilter={false}
            className="max-sm:min-h-0 max-sm:flex-1 max-sm:**:data-[slot=command-input-wrapper]:h-12 max-sm:**:data-[slot=command-input-wrapper]:pr-12"
          >
            <CommandInput value={input} onValueChange={setInput} placeholder={copy.command.placeholder} className="max-sm:text-base" />
            <CommandList className="max-sm:max-h-none max-sm:flex-1">
              {term.length > 0 && search.isSuccess ? <CommandEmpty>{copy.command.empty}</CommandEmpty> : null}
              {hits.map((hit) => (
                <CommandItem
                  key={`${hit.kind}:${hit.id}`}
                  value={`${hit.kind}:${hit.id}`}
                  className="max-lg:min-h-10"
                  onSelect={() => {
                    void navigate({ href: hitPath(hit) })
                    setOpenAndReset(false)
                  }}
                >
                  <span className="w-20 shrink-0 text-[11px] leading-tight text-muted-foreground">{copy.command.kind[hit.kind]}</span>
                  <span className="min-w-0 flex-1 truncate">
                    {hit.label}
                    {hit.detail ? <span className="ml-2 text-muted-foreground">{hit.detail}</span> : null}
                  </span>
                  {hit.worst ? <PriorityDot priority={hit.worst} /> : null}
                </CommandItem>
              ))}
              {term.length > 0 && search.data?.truncated ? <p className="px-3 py-2 text-[11px] text-muted-foreground">{copy.command.truncated}</p> : null}
            </CommandList>
          </Command>
          <DialogClose asChild>
            <Button variant="ghost" size="icon" className="absolute top-1 right-1 size-10 sm:hidden" aria-label={copy.shell.close}>
              <XIcon aria-hidden="true" />
            </Button>
          </DialogClose>
        </DialogContent>
      </Dialog>
    </>
  )
}
