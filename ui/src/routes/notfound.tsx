import { PageHeader } from '@/components/layout/PageHeader'
import { copy } from '@/lib/copy'

export function NotFoundPage() {
  return <PageHeader title={copy.notFound} />
}
