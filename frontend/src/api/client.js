const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';
const MOCK_API = import.meta.env.VITE_MOCK_API === 'true';

const mockReport = {
  id: 'scan_demo_8f3a1c',
  target_url: 'https://example.com',
  status: 'completed',
  created_at: '2026-08-29T10:00:00Z',
  completed_at: '2026-08-29T10:00:05Z',
  results: {
    overall_grade: 'B',
    modules: [
      {
        module_name: 'HTTP Security Headers', score: 'B', findings: [
          { check_name: 'Content-Security-Policy', severity: 'high', passed: false, detail: 'No Content-Security-Policy header was found.' },
          { check_name: 'X-Content-Type-Options', severity: 'info', passed: true, detail: 'The nosniff header is configured.' },
        ],
      },
      {
        module_name: 'Transport Layer Security', score: 'A', findings: [
          { check_name: 'HTTPS redirect', severity: 'low', passed: true, detail: 'HTTP requests are redirected to HTTPS.' },
          { check_name: 'Certificate validity', severity: 'info', passed: true, detail: 'The TLS certificate is currently valid.' },
        ],
      },
      {
        module_name: 'JWT Security', score: 'N/A', findings: [
          { check_name: 'JWT checks skipped', severity: 'info', passed: true, detail: 'JWT checks were skipped because no token was supplied.' },
        ],
      },
    ],
  },
};

let mockStatusCalls = 0;

async function request(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `Request failed with status ${response.status}`);
  }
  return response.json();
}

export async function createScan({ target_url, jwt_token, authorized }) {
  if (MOCK_API) {
    mockStatusCalls = 0;
    return { scan_id: mockReport.id };
  }
  return request('/scan', { method: 'POST', body: JSON.stringify({ target_url, jwt_token, authorized }) });
}

export async function getScanStatus(scanId) {
  if (MOCK_API) {
    mockStatusCalls += 1;
    return { status: mockStatusCalls === 1 ? 'running' : 'completed' };
  }
  return request(`/scan/${encodeURIComponent(scanId)}/status`);
}

export async function getScan(scanId) {
  if (MOCK_API) return { ...mockReport, id: scanId };
  return request(`/scan/${encodeURIComponent(scanId)}`);
}
