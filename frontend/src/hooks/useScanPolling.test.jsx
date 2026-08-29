import { act, renderHook } from '@testing-library/react';
import { vi } from 'vitest';

vi.mock('../api/client', () => ({ getScanStatus: vi.fn(), getScan: vi.fn() }));

import { getScan, getScanStatus } from '../api/client';
import { useScanPolling } from './useScanPolling';

test('polls until terminal status and returns the full report', async () => {
  vi.useFakeTimers();
  getScanStatus.mockResolvedValueOnce({ status: 'running' }).mockResolvedValueOnce({ status: 'completed' });
  const report = { id: 'scan-1', status: 'completed', results: { modules: [] } };
  getScan.mockResolvedValue(report);
  const { result } = renderHook(() => useScanPolling('scan-1'));
  await act(async () => { await Promise.resolve(); });
  expect(result.current.status).toBe('running');
  await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
  expect(result.current.report).toEqual(report);
  expect(result.current.status).toBe('completed');
  expect(getScanStatus).toHaveBeenCalledTimes(2);
  vi.useRealTimers();
});
