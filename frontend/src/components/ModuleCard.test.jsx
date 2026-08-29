import { render, screen } from '@testing-library/react';
import { ModuleCard } from './ModuleCard';

test.each([['A', 'score-a'], ['B', 'score-b'], ['C', 'score-c'], ['D', 'score-d'], ['F', 'score-f'], ['N/A', 'score-na']])('renders %s with its grade class', (score, className) => {
  render(<ModuleCard module={{ module_name: 'Test module', score, findings: [{ check_name: 'Test', severity: 'info', passed: true, detail: 'Detail' }] }} />);
  expect(screen.getByText(score)).toHaveClass(className);
});
