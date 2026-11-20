import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createQueryClient } from './api/client'
import { startLive } from './api/live'
import { createAppRouter } from './router'
import './styles.css'

const queryClient = createQueryClient()
const router = createAppRouter({ queryClient })
// The one EventSource of the app; components never open their own.
startLive(queryClient)

const root = document.getElementById('root')
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </StrictMode>,
  )
}
