/** Knowledge base state store. */

import { writable, derived } from 'svelte/store';
import type { KnowledgeQueryResponse, KnowledgeStatsResponse } from '$lib/api/knowledge';

export const queryResult = writable<KnowledgeQueryResponse | null>(null);
export const knowledgeStats = writable<KnowledgeStatsResponse | null>(null);
export const isQuerying = writable(false);
export const streamingAnswer = writable('');
export const queryError = writable<string | null>(null);
export const isScraping = writable(false);
export const scrapeMessage = writable<string | null>(null);

export const hasResults = derived(queryResult, ($r) => $r !== null && $r.num_sources > 0);

export function resetQueryState() {
	queryResult.set(null);
	streamingAnswer.set('');
	queryError.set(null);
	isQuerying.set(false);
}
