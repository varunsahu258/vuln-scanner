import { useState } from 'react';
import { FindingRow } from './FindingRow';

export function ModuleCard({ module }) {
  const isSkipped = module.score === 'N/A';
  const [isOpen, setIsOpen] = useState(false);
  const skipFinding = module.findings[0];
  if (isSkipped) return <article className="module-card module-skipped">
    <div className="module-header"><h3>{module.module_name}</h3><span className="score-badge score-na">N/A</span></div>
    <p className="skip-explanation">{skipFinding?.detail}</p>
  </article>;
  return <article className="module-card">
    <button className="module-header" type="button" onClick={() => setIsOpen((open) => !open)} aria-expanded={isOpen}>
      <h3>{module.module_name}</h3><span className={`score-badge score-${module.score.toLowerCase()}`}>{module.score}</span><span className="chevron" aria-hidden="true">{isOpen ? '⌃' : '⌄'}</span>
    </button>
    {isOpen && <ul className="findings-list">{module.findings.map((finding) => <FindingRow key={`${finding.check_name}-${finding.detail}`} finding={finding} />)}</ul>}
  </article>;
}
