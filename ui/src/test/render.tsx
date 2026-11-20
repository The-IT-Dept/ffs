import { QueryClientProvider } from '@tanstack/react-query'
import { type AnyRouter, createMemoryHistory, createRootRoute, createRouter, RouterProvider } from '@tanstack/react-router'
import { render } from '@testing-library/react'
import userEvent, { type UserEvent } from '@testing-library/user-event'
import type { ReactElement } from 'react'
import { createQueryClient } from '@/api/client'
import type { QueryClient } from '@tanstack/react-query'
import { type AppRouter, createAppRouter } from '@/router'

// renderApp renders the whole app at url, over a memory history and a query client that never
// retries.
export function renderApp(url: string): { router: AppRouter; queryClient: QueryClient; user: UserEvent } {
  const queryClient = createQueryClient({ retry: false })
  const router = createAppRouter({ queryClient, history: createMemoryHistory({ initialEntries: [url] }) })
  const user = userEvent.setup()
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  return { router, queryClient, user }
}

// renderWithRouter renders one element inside a router, for components that link or navigate.
export function renderWithRouter(ui: ReactElement): { router: AnyRouter; user: UserEvent } {
  const router = createRouter({
    routeTree: createRootRoute({ component: () => ui }),
    history: createMemoryHistory({ initialEntries: ['/'] }),
  })
  const user = userEvent.setup()
  render(
    <QueryClientProvider client={createQueryClient({ retry: false })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  return { router, user }
}
