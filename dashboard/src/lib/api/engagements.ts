/** Engagements API calls and SSE client. */

import { apiFetch } from './client';

export interface Engagement {
	id: string;
	client_name: string;
	targets: string[];
	objectives: string[];
	duration_days: number;
	status: 'created' | 'planning' | 'active' | 'paused' | 'completed' | 'failed' | 'cancelled';
	current_phase_id: string | null;
	total_findings: number;
	critical_findings: number;
	high_findings: number;
	risk_score: number;
	created_at: string;
	started_at: string | null;
	completed_at: string | null;
	paused_at: string | null;
	error: string | null;
	stealth_level: string;
	profile: string;
	phase_interval_minutes: number;
}

export interface EngagementPhase {
	id: string;
	engagement_id: string;
	phase_type: string;
	day_number: number;
	order_index: number;
	status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
	agent_key: string;
	scan_id: string | null;
	findings_count: number;
	progress: number;
	started_at: string | null;
	completed_at: string | null;
	error: string | null;
}

export interface EngagementDetail extends Engagement {
	phases: EngagementPhase[];
}

export interface CreateEngagementRequest {
	client_name: string;
	targets: string[];
	objectives?: string[];
	duration_days?: number;
	stealth_level?: string;
	phase_interval_minutes?: number;
}

export async function createEngagement(
	req: CreateEngagementRequest
): Promise<{ id: string; status: string }> {
	return apiFetch('/engagements', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}

export async function listEngagements(): Promise<Engagement[]> {
	return apiFetch<Engagement[]>('/engagements');
}

export async function getEngagement(id: string): Promise<EngagementDetail> {
	return apiFetch<EngagementDetail>(`/engagements/${id}`);
}

export async function getEngagementFindings(id: string): Promise<unknown[]> {
	return apiFetch(`/engagements/${id}/findings`);
}

export async function pauseEngagement(id: string): Promise<void> {
	await apiFetch(`/engagements/${id}/pause`, { method: 'POST' });
}

export async function resumeEngagement(id: string): Promise<void> {
	await apiFetch(`/engagements/${id}/resume`, { method: 'POST' });
}

export async function cancelEngagement(id: string): Promise<void> {
	await apiFetch(`/engagements/${id}`, { method: 'DELETE' });
}

export function connectEngagementSSE(
	id: string,
	onUpdate: (event: string, data: Record<string, unknown>) => void,
	onDone: (data: Record<string, unknown>) => void
): EventSource {
	const es = new EventSource(`/api/engagements/${id}/stream`);

	for (const evt of [
		'status',
		'plan_ready',
		'phase_start',
		'phase_update',
		'phase_complete',
		'phase_error',
		'log',
		'paused',
		'resumed'
	]) {
		es.addEventListener(evt, (e: MessageEvent) => {
			try {
				onUpdate(evt, JSON.parse(e.data));
			} catch {
				/* skip */
			}
		});
	}

	es.addEventListener('done', (e: MessageEvent) => {
		try {
			onDone(JSON.parse(e.data));
		} catch {
			/* skip */
		}
		es.close();
	});

	es.onerror = () => es.close();
	return es;
}
