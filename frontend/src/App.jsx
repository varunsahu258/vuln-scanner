import { useState } from 'react';
import { createScan } from './api/client';
import { ScanForm } from './components/ScanForm';
import { ScanProgress } from './components/ScanProgress';
import { ReportView } from './components/ReportView';
import { useScanPolling } from './hooks/useScanPolling';

export default function App() {
  const [scanId, setScanId] = useState(null);
  const [submitError, setSubmitError] = useState(null);
  const { status, report, error: pollingError } = useScanPolling(scanId);

  async function submitScan(payload) {
    setSubmitError(null);
    try { setScanId((await createScan(payload)).scan_id); } catch (error) { setSubmitError(error.message); }
  }
  function reset() { setScanId(null); setSubmitError(null); }

  return <main className="app-shell">
    <nav><span className="logo-mark">V</span><span>VulnScan</span></nav>
    {!scanId && <ScanForm onSubmit={submitScan} error={submitError} />}
    {scanId && pollingError && <section className="panel error-panel"><h1>Scan unavailable</h1><p role="alert">{pollingError}</p><button className="secondary-button" onClick={reset}>Try another scan</button></section>}
    {scanId && !pollingError && !report && <ScanProgress status={status} />}
    {report?.status === 'failed' && <section className="panel error-panel"><p className="eyebrow">Scan failed</p><h1>We could not complete this scan.</h1><p className="lead">Please verify that the target is reachable and try again.</p><button className="secondary-button" onClick={reset}>New Scan</button></section>}
    {report && report.status !== 'failed' && <ReportView report={report} onNewScan={reset} />}
  </main>;
}
