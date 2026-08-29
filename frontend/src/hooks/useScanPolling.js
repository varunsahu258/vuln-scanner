import { useEffect, useState } from 'react';
import { getScan, getScanStatus } from '../api/client';

const TERMINAL_STATUSES = new Set(['completed', 'failed']);

export function useScanPolling(scanId) {
  const [status, setStatus] = useState(scanId ? 'pending' : null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!scanId) return undefined;
    let cancelled = false;
    let timerId;

    const poll = async () => {
      try {
        const statusResponse = await getScanStatus(scanId);
        if (cancelled) return;
        setStatus(statusResponse.status);
        if (TERMINAL_STATUSES.has(statusResponse.status)) {
          const scanReport = await getScan(scanId);
          if (!cancelled) setReport(scanReport);
          return;
        }
        timerId = window.setTimeout(poll, 2000);
      } catch (pollError) {
        if (!cancelled) setError(pollError.message || 'Unable to retrieve scan status.');
      }
    };

    poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timerId);
    };
  }, [scanId]);

  return { status, report, error };
}
