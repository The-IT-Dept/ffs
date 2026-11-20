import { Fragment, type ReactNode } from 'react'
import { AppLink } from './AppLink'

export interface Crumb {
  label: string
  href?: string
}

// PageHeader is a page's breadcrumbs, kind, title, one-line summary and actions. On a narrow screen
// the actions wrap under the title, long breadcrumbs and summaries (image references, digests)
// break anywhere, and a title too long for its line is truncated with the full text as its title.
export function PageHeader({ crumbs, kind, title, sub, actions }: { crumbs?: Crumb[]; kind?: string; title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-start gap-x-4 gap-y-2">
      <div className="min-w-0 flex-[1_1_16rem]">
        {crumbs && crumbs.length > 0 ? (
          <nav aria-label="Breadcrumb" className="mb-1 text-[11px] wrap-anywhere text-muted-foreground">
            {crumbs.map((c, i) => (
              <Fragment key={`${i}:${c.label}`}>
                {i > 0 ? <span aria-hidden="true" className="mx-1">›</span> : null}
                {c.href ? (
                  <AppLink href={c.href} className="hover:text-foreground hover:underline max-lg:inline-flex max-lg:min-h-10 max-lg:items-center">
                    {c.label}
                  </AppLink>
                ) : (
                  <span>{c.label}</span>
                )}
              </Fragment>
            ))}
          </nav>
        ) : null}
        {kind ? <div className="text-[9.5px] font-medium tracking-wider text-muted-foreground uppercase">{kind}</div> : null}
        <h1 className="truncate text-[17px] leading-tight font-semibold" title={typeof title === 'string' ? title : undefined}>
          {title}
        </h1>
        {sub ? <div className="mt-0.5 text-[11.5px] wrap-anywhere text-muted-foreground">{sub}</div> : null}
      </div>
      {actions ? <div className="flex max-w-full shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  )
}
