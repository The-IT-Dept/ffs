import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

// cn joins class names and resolves conflicting Tailwind utilities, the later one winning.
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
