import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createRef } from 'react'
import { expect, test } from 'vitest'
import { ExplorerTable } from '@/components/explorer/ExplorerTable'
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import { Table, TableBody, TableCell, TableFooter, TableHead, TableHeader, TableRow } from '@/components/ui/table'

test('a sheet focuses its content on open even when the caller passes a ref', async () => {
  const ref = createRef<HTMLDivElement>()
  const user = userEvent.setup()
  render(
    <Sheet>
      <SheetTrigger>Open</SheetTrigger>
      <SheetContent ref={ref} aria-describedby={undefined}>
        <SheetTitle>Sheet</SheetTitle>
        <input aria-label="Field" />
      </SheetContent>
    </Sheet>,
  )
  await user.click(screen.getByRole('button', { name: 'Open' }))
  const dialog = await screen.findByRole('dialog', { name: 'Sheet' })
  expect(ref.current).toBe(dialog)
  expect(dialog).toHaveFocus()
})

test('row rules sit on the cells, which border-separate draws', () => {
  render(
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow>
          <TableCell>web</TableCell>
        </TableRow>
      </TableBody>
      <TableFooter>
        <TableRow>
          <TableCell>total</TableCell>
        </TableRow>
      </TableFooter>
    </Table>,
  )
  const [head, , foot] = screen.getAllByRole('rowgroup')
  // The header's rule comes from its row's cells alone.
  expect(head.className).not.toMatch(/border/)
  expect(screen.getAllByRole('row')[0]).toHaveClass('[&>*]:border-b')
  // The footer rules its first row's cells once, not itself and not every row.
  expect(foot).toHaveClass('[&>tr:first-child>*]:border-t')
  expect(foot).not.toHaveClass('[&>tr>*]:border-t')
  expect(foot).not.toHaveClass('border-t')
})

test('explorer rows and sort buttons are 40 px tall below lg', () => {
  render(
    <ExplorerTable
      columns={[{ id: 'name', header: 'Name', sort: 'name', cell: (r: { name: string }) => r.name }]}
      rows={[{ name: 'web' }]}
      rowKey={(r) => r.name}
      sort="name"
      onSort={() => {}}
    />,
  )
  expect(screen.getByRole('button', { name: /Name/ })).toHaveClass('h-6', 'max-lg:h-10')
  for (const row of screen.getAllByRole('row')) expect(row).toHaveClass('h-[30px]', 'max-lg:h-10')
})
