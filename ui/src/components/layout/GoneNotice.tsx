import { useRouterState } from '@tanstack/react-router'
import { copy } from '@/lib/copy'
import { isOneOf, SCOPE_KINDS } from '@/lib/enums'
import type { ScopeKind } from '@/lib/scope'

declare module '@tanstack/react-router' {
  interface HistoryState {
    // The kind of scope whose page handed over to this one because it no longer exists.
    gone?: ScopeKind
  }
}

// goneState is the history state a page sets when it hands over to a list because its object no
// longer exists (a 404 not_found for its scope): navigate({ to, replace: true, state: goneState(kind) }).
export function goneState(kind: ScopeKind): { gone: ScopeKind } {
  return { gone: kind }
}

// GoneNotice says that the page the user asked for no longer exists, on the list it handed over
// to. The notice lives in that one history entry, so it is gone after the next navigation.
export function GoneNotice() {
  const gone: unknown = useRouterState({ select: (s) => s.location.state.gone })
  if (!isOneOf(SCOPE_KINDS, gone)) return null
  return (
    <p role="status" className="mb-3 rounded-md border border-dashed px-3 py-2 text-[12px] text-muted-foreground">
      {copy.gone(gone)}
    </p>
  )
}
