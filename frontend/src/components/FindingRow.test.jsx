import { render, screen } from '@testing-library/react';
import { FindingRow } from './FindingRow';

test.each(['info', 'low', 'medium', 'high'])('renders %s with its severity class', (severity) => {
  render(<FindingRow finding={{ severity, check_name: 'Example check', detail: 'Example detail', passed: true }} />);
  expect(screen.getByText(severity)).toHaveClass(`severity-${severity}`);
});
