import { apiFetch } from './client';

export interface RemediationFinding {
  id: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'open' | 'assigned' | 'in_progress' | 'remediated' | 'verified';
  assigned_to: string | null;
  priority: 'critical' | 'high' | 'medium' | 'low';
  sla_deadline: string | null;
  client_id: string;
}

export interface RemediationNote {
  id: number;
  finding_id: number;
  user: string;
  note: string;
  created_at: string;
}

export interface RemediationMetrics {
  mttr_days: number;
  sla_compliance_pct: number;
  overdue_count: number;
  by_status: Record<string, number>;
}

export interface FindingHistory {
  finding_id: number;
  timestamp: string;
  action: string;
  user: string;
  details: Record<string, unknown>;
}

export async function assignFinding(
  findingId: number,
  assignedTo: string,
  priority: string
): Promise<void> {
  return apiFetch<void>(`/remediation/findings/${findingId}/assign`, {
    method: 'POST',
    body: JSON.stringify({ assigned_to: assignedTo, priority })
  });
}

export async function addNote(findingId: number, note: string): Promise<RemediationNote> {
  return apiFetch<RemediationNote>(`/remediation/findings/${findingId}/notes`, {
    method: 'POST',
    body: JSON.stringify({ note })
  });
}

export async function scheduleRetest(findingId: number, scheduledDate: string): Promise<void> {
  return apiFetch<void>(`/remediation/findings/${findingId}/retest`, {
    method: 'POST',
    body: JSON.stringify({ scheduled_date: scheduledDate })
  });
}

export async function listOverdue(): Promise<RemediationFinding[]> {
  return apiFetch<RemediationFinding[]>('/remediation/overdue');
}

export async function getMetrics(): Promise<RemediationMetrics> {
  return apiFetch<RemediationMetrics>('/remediation/metrics');
}

export async function getFindingHistory(findingId: number): Promise<FindingHistory[]> {
  return apiFetch<FindingHistory[]>(`/remediation/findings/${findingId}/history`);
}

export async function updateFindingStatus(
  findingId: number,
  status: RemediationFinding['status']
): Promise<void> {
  return apiFetch<void>(`/remediation/findings/${findingId}/status`, {
    method: 'PUT',
    body: JSON.stringify({ status })
  });
}
