// The theme choice is stored under the same key public/theme.js reads before the first paint.
export type ThemeChoice = 'light' | 'dark' | 'system'
export const THEME_KEY = 'ffs-theme'

const DARK_QUERY = '(prefers-color-scheme: dark)'

export function readTheme(): ThemeChoice {
  try {
    const v = localStorage.getItem(THEME_KEY)
    if (v === 'light' || v === 'dark' || v === 'system') return v
  } catch {
    // Storage can be unavailable (privacy settings); the system preference applies.
  }
  return 'system'
}

export function systemQuery(): MediaQueryList | undefined {
  return typeof window.matchMedia === 'function' ? window.matchMedia(DARK_QUERY) : undefined
}

export function applyTheme(c: ThemeChoice): void {
  try {
    localStorage.setItem(THEME_KEY, c)
  } catch {
    // The class below still applies for this page.
  }
  const dark = c === 'dark' || (c === 'system' && (systemQuery()?.matches ?? false))
  document.documentElement.classList.toggle('dark', dark)
}

export function nextTheme(c: ThemeChoice): ThemeChoice {
  if (c === 'light') return 'dark'
  if (c === 'dark') return 'system'
  return 'light'
}
