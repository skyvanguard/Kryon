import { apiFetch } from './client';

export interface Client {
	id: string;
	name: string;
	industry: string;
	contact_email: string;
	notes: string;
	created_at: string;
}

export interface ClientProgress {
	client_id: string;
	total_scans: number;
	total_findings: number;
	critical: number;
	high: number;
	medium: number;
	low: number;
	remediated: number;
	risk_score: number;
}

export async function listClients(offset = 0, limit = 50): Promise<Client[]> {
	const params = new URLSearchParams({ offset: offset.toString(), limit: limit.toString() });
	return apiFetch<Client[]>(`/clients?${params}`);
}

export async function getClient(id: string): Promise<Client> {
	return apiFetch<Client>(`/clients/${id}`);
}

export async function createClient(data: Partial<Client>): Promise<Client> {
	return apiFetch<Client>('/clients', {
		method: 'POST',
		body: JSON.stringify(data)
	});
}

export async function updateClient(id: string, data: Partial<Client>): Promise<Client> {
	return apiFetch<Client>(`/clients/${id}`, {
		method: 'PUT',
		body: JSON.stringify(data)
	});
}

export async function deleteClient(id: string): Promise<void> {
	await apiFetch(`/clients/${id}`, { method: 'DELETE' });
}

export async function getClientFindings(id: string, status?: string): Promise<unknown[]> {
	const params = status ? `?status=${status}` : '';
	return apiFetch<unknown[]>(`/clients/${id}/findings${params}`);
}

export async function getClientProgress(id: string): Promise<ClientProgress> {
	return apiFetch<ClientProgress>(`/clients/${id}/progress`);
}

export async function getClientTimeline(id: string): Promise<unknown[]> {
	return apiFetch<unknown[]>(`/clients/${id}/timeline`);
}
