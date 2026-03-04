/** Run API calls and SSE client. */

import { apiFetch } from './client';

export interface RunRequest {
	agent_key: string;
	input: string;
	session_id?: string;
	stream?: boolean;
	max_turns?: number;
}

export interface RunResponse {
	run_id: string;
	status: string;
	output: string;
	agent: string;
	usage: Record<string, unknown>;
}

export async function createRun(req: RunRequest): Promise<RunResponse> {
	return apiFetch<RunResponse>('/runs', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}

export interface RunStatus {
	run_id: string;
	status: string;
	agent: string | null;
	output: string | null;
}

export async function getRunStatus(runId: string): Promise<RunStatus> {
	return apiFetch<RunStatus>(`/runs/${runId}`);
}

export async function cancelRun(runId: string): Promise<void> {
	await apiFetch(`/runs/${runId}`, { method: 'DELETE' });
}

export interface SSEEvent {
	event: string;
	data: Record<string, unknown>;
}

export function connectSSE(
	runId: string,
	onEvent: (evt: SSEEvent) => void,
	onDone: (output: string) => void,
	onError: (err: string) => void
): EventSource {
	const es = new EventSource(`/api/v1/runs/${runId}/stream`);

	for (const eventType of [
		'message_output_created',
		'tool_called',
		'tool_output',
		'agent_updated',
		'handoff_requested',
		'handoff_occured'
	]) {
		es.addEventListener(eventType, (e: MessageEvent) => {
			try {
				const data = JSON.parse(e.data);
				onEvent({ event: eventType, data });
			} catch {
				/* skip malformed */
			}
		});
	}

	es.addEventListener('done', (e: MessageEvent) => {
		const data = JSON.parse(e.data);
		onDone(data.output || '');
		es.close();
	});

	es.addEventListener('error', (e: MessageEvent) => {
		if (e.data) {
			const data = JSON.parse(e.data);
			onError(data.error || 'Unknown error');
		}
		es.close();
	});

	es.onerror = () => {
		es.close();
	};

	return es;
}

export interface SessionResponse {
	session_id: string;
	agent_key: string;
	created_at: string;
	message_count: number;
}

export async function createSession(agentKey: string): Promise<SessionResponse> {
	return apiFetch<SessionResponse>('/sessions', {
		method: 'POST',
		body: JSON.stringify({ agent_key: agentKey })
	});
}

export async function fetchSessions(): Promise<SessionResponse[]> {
	return apiFetch<SessionResponse[]>('/sessions');
}
