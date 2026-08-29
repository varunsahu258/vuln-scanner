export function FindingRow({ finding }) {
  return <li className="finding-row">
    <span className={`severity-badge severity-${finding.severity}`}>{finding.severity}</span>
    <div><strong>{finding.check_name}</strong><p>{finding.detail}</p></div>
  </li>;
}
