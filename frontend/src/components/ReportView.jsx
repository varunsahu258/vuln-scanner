import { ModuleCard } from './ModuleCard';

export function ReportView({ report, onNewScan }) {
  const results = report.results;
  return <section className="report-view">
    <header className="report-header">
      <div><p className="eyebrow">Scan complete</p><h1>Security report</h1><p className="target-url">{report.target_url}</p></div>
      <div className={`overall-grade score-${results.overall_grade.toLowerCase()}`} aria-label={`Overall grade ${results.overall_grade}`}>{results.overall_grade}</div>
    </header>
    <div className="module-list">{results.modules.map((module) => <ModuleCard key={module.module_name} module={module} />)}</div>
    <button className="secondary-button" type="button" onClick={onNewScan}>New Scan</button>
  </section>;
}
