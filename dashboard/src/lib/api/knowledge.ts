/** Knowledge base API calls and SSE client. */

import { apiFetch } from './client';

export interface KnowledgeQueryRequest {
	question: string;
	top_k?: number;
	source_filter?: string | null;
	use_llm?: boolean;
}

export interface KnowledgeQueryResponse {
	question: string;
	answer: string | null;
	sources: KnowledgeSource[];
	num_sources: number;
}

export interface KnowledgeSource {
	content: string;
	metadata: Record<string, unknown>;
	score: number;
}

export interface KnowledgeAddRequest {
	content: string;
	source: string;
	metadata?: Record<string, unknown>;
}

export interface KnowledgeAddResponse {
	doc_id: string;
	success: boolean;
}

export interface KnowledgeStatsResponse {
	total_documents: number;
	sources: Record<string, number>;
	llm_configured: boolean;
	llm_model: string;
}

export interface ScrapeRequest {
	sources?: string[];
	nvd_days?: number;
	nvd_count?: number;
}

export interface ScrapeResponse {
	task_id: string;
	status: string;
	message: string;
}

export interface ScrapeStatus {
	task_id: string;
	status: string;
	documents_added: number;
	errors: string[];
}

export async function queryKnowledge(req: KnowledgeQueryRequest): Promise<KnowledgeQueryResponse> {
	return apiFetch<KnowledgeQueryResponse>('/knowledge/query', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}

export async function addKnowledge(req: KnowledgeAddRequest): Promise<KnowledgeAddResponse> {
	return apiFetch<KnowledgeAddResponse>('/knowledge/add', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}

export async function getKnowledgeStats(): Promise<KnowledgeStatsResponse> {
	return apiFetch<KnowledgeStatsResponse>('/knowledge/stats');
}

export async function startScrape(req: ScrapeRequest = {}): Promise<ScrapeResponse> {
	return apiFetch<ScrapeResponse>('/knowledge/scrape', {
		method: 'POST',
		body: JSON.stringify(req)
	});
}

export async function getScrapeStatus(taskId: string): Promise<ScrapeStatus> {
	return apiFetch<ScrapeStatus>(`/knowledge/scrape/${taskId}`);
}

export function connectKnowledgeSSE(
	question: string,
	onToken: (token: string) => void,
	onDone: (answer: string) => void
): EventSource {
	const params = new URLSearchParams({ question });
	const es = new EventSource(`/api/knowledge/query/stream?${params}`);

	es.onmessage = (e: MessageEvent) => {
		try {
			const data = JSON.parse(e.data);
			if (data.token) {
				onToken(data.token);
			}
		} catch {
			/* skip */
		}
	};

	es.addEventListener('done', (e: MessageEvent) => {
		try {
			const data = JSON.parse(e.data);
			onDone(data.answer || '');
		} catch {
			/* skip */
		}
		es.close();
	});

	es.onerror = () => {
		es.close();
	};

	return es;
}
