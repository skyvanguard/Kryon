import { apiFetch } from './client';

export interface AdminUser {
	id: string;
	username: string;
	role: string;
	created_at: string;
	last_login: string | null;
}

export interface AuditEntry {
	id: string;
	timestamp: string;
	user: string;
	action: string;
	resource: string;
	detail: string;
	ip: string;
}

export interface SystemHealth {
	status: string;
	uptime_seconds: number;
	db_size_bytes: number;
	total_scans: number;
	total_findings: number;
	total_clients: number;
	rag_documents: number;
	ai_provider: string;
}

export async function listUsers(): Promise<AdminUser[]> {
	return apiFetch<AdminUser[]>('/admin/users');
}

export async function createUser(data: {
	username: string;
	password: string;
	role: string;
}): Promise<AdminUser> {
	return apiFetch<AdminUser>('/admin/users', {
		method: 'POST',
		body: JSON.stringify(data)
	});
}

export async function deleteUser(id: string): Promise<void> {
	await apiFetch(`/admin/users/${id}`, { method: 'DELETE' });
}

export async function getAuditLog(
	offset = 0,
	limit = 100,
	action?: string
): Promise<AuditEntry[]> {
	const params = new URLSearchParams({
		offset: offset.toString(),
		limit: limit.toString()
	});
	if (action) params.set('action', action);
	return apiFetch<AuditEntry[]>(`/audit/logs?${params}`);
}

export async function getAdminHealth(): Promise<SystemHealth> {
	return apiFetch<SystemHealth>('/admin/health');
}

export async function triggerBackup(): Promise<{ path: string }> {
	return apiFetch<{ path: string }>('/admin/backup', { method: 'POST' });
}
