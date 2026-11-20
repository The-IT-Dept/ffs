import { ApiProblem } from '@/api/client'
import { copy } from '@/lib/copy'

// ProblemNotice shows why a request failed: a missing object reads as the not-found copy, any
// other problem as its title and detail.
export function ProblemNotice({ error }: { error: unknown }) {
  let title: string
  let detail: string | undefined
  if (error instanceof ApiProblem) {
    if (error.status === 404) title = copy.notFound
    else {
      title = error.title
      detail = error.detail
    }
  } else if (error instanceof Error) {
    title = error.message
  } else {
    title = String(error)
  }
  return (
    <div role="alert" className="rounded-md border px-4 py-3 text-[13px] text-muted-foreground">
      <p className="font-medium text-foreground">{title}</p>
      {detail ? <p className="mt-1">{detail}</p> : null}
    </div>
  )
}
