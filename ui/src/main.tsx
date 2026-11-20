import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'

const root = document.getElementById('root')
if (root) {
  createRoot(root).render(
    <StrictMode>
      <p className="p-6 text-sm text-muted-foreground">ffs</p>
    </StrictMode>,
  )
}
