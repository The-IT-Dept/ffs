import { Fragment, type ReactNode } from 'react'
import { AppLink } from './AppLink'

export interface Crumb {
  label: string
  href?: string
}

export function PageHeader({ crumbs, kind, title, sub, actions }: { crumbs?: Crumb[]; kind?: string; title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex items-start gap-4">
      <div className="min-w-0 flex-1">
        {crumbs && crumbs.length > 0 ? (
          <nav aria-label="Breadcrumb" className="mb-1 text-[11px] text-muted-foreground">
            {crumbs.map((c, i) => (
              <Fragment key={`${i}:${c.label}`}>
                {i > 0 ? <span aria-hidden="true" className="mx-1">›</span> : null}
                {c.href ? (
                  <AppLink href={c.href} className="hover:text-foreground hover:underline">
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
        <h1 className="truncate text-[17px] leading-tight font-semibold">{title}</h1>
        {sub ? <div className="mt-0.5 text-[11.5px] text-muted-foreground">{sub}</div> : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  )
}
