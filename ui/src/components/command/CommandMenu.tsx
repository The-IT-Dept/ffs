import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { SearchIcon } from 'lucide-react'
import { useEffect, useState } from 'react'
import { apiQuery } from '@/api/client'
import { PriorityDot } from '@/components/signals/PriorityDot'
import { Button } from '@/components/ui/button'
import { Command, CommandEmpty, CommandInput, CommandItem, CommandList } from '@/components/ui/command'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { copy } from '@/lib/copy'
import { useDebounced } from '@/lib/hooks'
import { hitPath } from '@/lib/links'

export const SEARCH_DEBOUNCE_MS = 150

// CommandMenu is ⌘K / Ctrl-K: a jump to any object, searched on the server. It composes Dialog and
// Command itself because shadcn's CommandDialog cannot turn off cmdk's client-side filtering.
export function CommandMenu() {
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
      <Button variant="outline" size="sm" className="h-7 gap-2 px-2 text-[12px] font-normal text-muted-foreground" onClick={() => setOpen(true)}>
        <SearchIcon aria-hidden="true" />
        <span>{copy.command.open}</span>
        <kbd className="rounded border bg-muted px-1 font-sans text-[10px]">⌘K</kbd>
      </Button>
      <Dialog open={open} onOpenChange={setOpenAndReset}>
        <DialogContent className="overflow-hidden p-0" showCloseButton={false}>
          <DialogTitle className="sr-only">{copy.command.open}</DialogTitle>
          <DialogDescription className="sr-only">{copy.command.placeholder}</DialogDescription>
          <Command shouldFilter={false}>
            <CommandInput value={input} onValueChange={setInput} placeholder={copy.command.placeholder} />
            <CommandList>
              {term.length > 0 && search.isSuccess ? <CommandEmpty>{copy.command.empty}</CommandEmpty> : null}
              {hits.map((hit) => (
                <CommandItem
                  key={`${hit.kind}:${hit.id}`}
                  value={`${hit.kind}:${hit.id}`}
                  onSelect={() => {
                    void navigate({ href: hitPath(hit) })
                    setOpenAndReset(false)
                  }}
                >
                  <span className="w-20 shrink-0 text-[11px] text-muted-foreground">{copy.command.kind[hit.kind]}</span>
                  <span className="min-w-0 flex-1 truncate">
                    {hit.label}
                    {hit.detail ? <span className="ml-2 text-muted-foreground">{hit.detail}</span> : null}
                  </span>
                  {hit.worst ? <PriorityDot priority={hit.worst} /> : null}
                </CommandItem>
              ))}
            </CommandList>
          </Command>
        </DialogContent>
      </Dialog>
    </>
  )
}
