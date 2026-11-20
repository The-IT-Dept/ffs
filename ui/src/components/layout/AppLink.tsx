import { useNavigate } from '@tanstack/react-router'
import type { AnchorHTMLAttributes, MouseEvent } from 'react'

// AppLink is a plain <a href> that navigates in the app on a plain left click and leaves every
// other click (new tab, new window, download) to the browser.
export function AppLink({ href, onClick, ...rest }: { href: string } & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'>) {
  const navigate = useNavigate()
  const handle = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e)
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || rest.target) return
    e.preventDefault()
    void navigate({ href })
  }
  return <a href={href} onClick={handle} {...rest} />
}
