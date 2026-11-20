import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

// cn joins class names and resolves conflicting Tailwind utilities, the later one winning.
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

// touchLink makes an inline link a 40 px touch target below the lg breakpoint (spec §12); touchBlock
// does the same for a link that sits on its own line.
export const touchLink = 'max-lg:inline-flex max-lg:min-h-10 max-lg:items-center'
export const touchBlock = 'max-lg:flex max-lg:min-h-10 max-lg:items-center'
