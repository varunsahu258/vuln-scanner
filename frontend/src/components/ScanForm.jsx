import { useState } from 'react';

export function ScanForm({ onSubmit, error }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [jwtToken, setJwtToken] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [urlError, setUrlError] = useState('');
  const canSubmit = Boolean(targetUrl.trim()) && authorized;

  function validateUrl(value) {
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol);
    } catch {
      return false;
    }
  }

  function handleSubmit(event) {
    event.preventDefault();
    if (!validateUrl(targetUrl)) {
      setUrlError('Enter a valid HTTP or HTTPS URL.');
      return;
    }
    setUrlError('');
    onSubmit({ target_url: targetUrl.trim(), jwt_token: jwtToken.trim() || null, authorized });
  }

  return <section className="panel scan-form-panel">
    <p className="eyebrow">Security posture scanner</p>
    <h1>Scan your web application.</h1>
    <p className="lead">Run focused security checks and review clear, actionable findings.</p>
    <form onSubmit={handleSubmit} noValidate>
      <label htmlFor="target-url">Target URL</label>
      <input id="target-url" name="target_url" type="url" placeholder="https://example.com" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} onBlur={() => targetUrl && setUrlError(validateUrl(targetUrl) ? '' : 'Enter a valid HTTP or HTTPS URL.')} required />
      {urlError && <p className="field-error" role="alert">{urlError}</p>}
      {error && <p className="field-error" role="alert">{error}</p>}
      <button className="advanced-toggle" type="button" onClick={() => setAdvancedOpen((open) => !open)} aria-expanded={advancedOpen}>Advanced <span aria-hidden="true">{advancedOpen ? '−' : '+'}</span></button>
      {advancedOpen && <div className="advanced-fields">
        <label htmlFor="jwt-token">JWT token <span>(optional)</span></label>
        <textarea id="jwt-token" name="jwt_token" value={jwtToken} onChange={(event) => setJwtToken(event.target.value)} placeholder="Paste a token to enable JWT checks" rows="4" />
      </div>}
      <label className="consent"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /> <span>I confirm I have permission to scan this target</span></label>
      <button className="primary-button" type="submit" disabled={!canSubmit}>Start scan</button>
    </form>
  </section>;
}
