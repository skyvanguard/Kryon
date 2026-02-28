import { apiFetch } from './client';

export interface ScopeRule {
	id: string;
	target: string;
	rule_type: string;
	action: string;
	notes: string;
	created_at: string;
}

export async function listScopeRules(): Promise<ScopeRule[]> {
	return apiFetch<ScopeRule[]>('/scope/rules');
}

export async function createScopeRule(data: Partial<ScopeRule>): Promise<ScopeRule> {
	return apiFetch<ScopeRule>('/scope/rules', {
		method: 'POST',
		body: JSON.stringify(data)
	});
}

export async function deleteScopeRule(id: string): Promise<void> {
	await apiFetch(`/scope/rules/${id}`, { method: 'DELETE' });
}
