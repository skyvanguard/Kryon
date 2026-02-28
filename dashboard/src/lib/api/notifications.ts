import { apiFetch } from './client';

export interface NotificationChannel {
  id: number;
  name: string;
  channel_type: 'email' | 'slack' | 'teams' | 'pagerduty' | 'webhook';
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
}

export interface NotificationRule {
  id: number;
  event_type: string;
  severity_filter: string[];
  client_filter: string | null;
  channel_ids: number[];
  digest_mode: boolean;
  created_at: string;
}

export interface NotificationLogEntry {
  id: number;
  timestamp: string;
  channel_id: number;
  channel_name: string;
  event_type: string;
  status: 'success' | 'failed';
  error_message: string | null;
}

export async function listChannels(): Promise<NotificationChannel[]> {
  return apiFetch<NotificationChannel[]>('/notifications/channels');
}

export async function createChannel(
  data: Omit<NotificationChannel, 'id' | 'created_at'>
): Promise<NotificationChannel> {
  return apiFetch<NotificationChannel>('/notifications/channels', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

export async function updateChannel(
  id: number,
  data: Partial<Omit<NotificationChannel, 'id' | 'created_at'>>
): Promise<NotificationChannel> {
  return apiFetch<NotificationChannel>(`/notifications/channels/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data)
  });
}

export async function deleteChannel(id: number): Promise<void> {
  return apiFetch<void>(`/notifications/channels/${id}`, {
    method: 'DELETE'
  });
}

export async function listRules(): Promise<NotificationRule[]> {
  return apiFetch<NotificationRule[]>('/notifications/rules');
}

export async function createRule(
  data: Omit<NotificationRule, 'id' | 'created_at'>
): Promise<NotificationRule> {
  return apiFetch<NotificationRule>('/notifications/rules', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

export async function deleteRule(id: number): Promise<void> {
  return apiFetch<void>(`/notifications/rules/${id}`, {
    method: 'DELETE'
  });
}

export async function getNotificationLog(
  limit = 100,
  offset = 0
): Promise<NotificationLogEntry[]> {
  return apiFetch<NotificationLogEntry[]>(
    `/notifications/log?limit=${limit}&offset=${offset}`
  );
}

export async function testChannel(id: number): Promise<{ success: boolean; message: string }> {
  return apiFetch<{ success: boolean; message: string }>(
    `/notifications/channels/${id}/test`,
    {
      method: 'POST'
    }
  );
}
