import { render, screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import { coverageFigure, rowSignals } from '@/test/fixtures'
import { CoverageFigureText } from './CoverageFigureText'
import { PriorityCount } from './PriorityCount'
import { PriorityDot } from './PriorityDot'
import { SignalCells } from './SignalCells'
import { priorityTone } from './tone'

test('spends colour only on urgent, high and medium dots', () => {
  render(
    <>
      <PriorityCount priority="urgent" n={3} />
      <PriorityCount priority="high" n={0} />
      <PriorityDot priority="medium" />
      <PriorityDot priority="low" />
    </>,
  )
  expect(screen.getByText('3')).toHaveClass('text-(--urgent)')
  expect(screen.getByText('0')).toHaveClass('text-muted-foreground')
  // High text takes the darker text orange; high dots keep the fill.
  expect(priorityTone.high.text).toBe('text-(--high-text)')
  expect(priorityTone.high.dot).toBe('bg-(--high)')
  expect(screen.getByRole('img', { name: 'medium' })).toHaveClass('bg-(--medium)')
  expect(screen.getByRole('img', { name: 'low' }).className).not.toMatch(/--(urgent|high|medium)/)
})

test('marks coverage gaps with the hatched treatment, never a colour', () => {
  render(
    <>
      <PriorityDot priority="none" gap />
      <CoverageFigureText figure={coverageFigure({ inUse: 6, seenInto: 5, full: 4 })} secondary />
    </>,
  )
  expect(screen.getByRole('img', { name: 'coverage gap' })).toHaveClass('hatched')
  expect(screen.getByText('4/6').closest('.hatched')).not.toBeNull()
  expect(screen.getByText(/5 seen into/)).toBeInTheDocument()
})

test('renders unknown node signals as —', () => {
  render(
    <table>
      <tbody>
        <tr>
          <SignalCells signals={rowSignals({ privileged: null, saPower: null })} max={10} />
        </tr>
      </tbody>
    </table>,
  )
  expect(screen.getAllByText('—')).toHaveLength(2)
})
