export function ScanProgress({ status }) {
  return <section className="panel progress-panel" aria-live="polite">
    <div className="pulse-indicator" aria-hidden="true"><span /><span /><span /></div>
    <p className="eyebrow">Scan in progress</p>
    <h1>{status === 'pending' ? 'Preparing your scan…' : 'Checking your target…'}</h1>
    <p className="lead">This usually takes a moment. We will show your report as soon as it is ready.</p>
  </section>;
}
