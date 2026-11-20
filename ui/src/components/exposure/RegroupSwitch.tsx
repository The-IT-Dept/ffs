import { GroupSwitch } from '@/components/explorer/GroupSwitch'
import { copy } from '@/lib/copy'

type Group = 'entry' | 'namespace' | 'node'

const options: readonly { value: Group; label: string }[] = [
  { value: 'entry', label: copy.regroup.entry },
  { value: 'namespace', label: copy.regroup.namespace },
  { value: 'node', label: copy.regroup.node },
]

// RegroupSwitch regroups the exposure table by entry point, by namespace, or by node group.
export function RegroupSwitch({ value, onChange }: { value: Group; onChange: (g: Group) => void }) {
  return <GroupSwitch value={value} options={options} onChange={(v) => onChange(v as Group)} />
}
