import { fireEvent, render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import { ScanForm } from './ScanForm';

test('only enables submission after URL and authorization are provided', () => {
  render(<ScanForm onSubmit={vi.fn()} />);
  const submit = screen.getByRole('button', { name: 'Start scan' });
  expect(submit).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Target URL'), { target: { value: 'https://example.com' } });
  expect(submit).toBeDisabled();
  fireEvent.click(screen.getByLabelText(/I confirm I have permission/i));
  expect(submit).toBeEnabled();
});
