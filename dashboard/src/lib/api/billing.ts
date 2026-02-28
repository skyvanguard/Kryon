import { apiFetch } from './client';

export interface License {
  tier: 'community' | 'professional' | 'enterprise' | 'military';
  valid_until: string | null;
  features: string[];
  active: boolean;
}

export interface UsageStats {
  scans_count: number;
  scans_limit: number;
  findings_count: number;
  findings_limit: number;
  storage_bytes: number;
  storage_limit_bytes: number;
  users_count: number;
  users_limit: number;
}

export interface Feature {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  tier_required: string;
}

export interface Limits {
  scans_per_month: number;
  concurrent_scans: number;
  max_users: number;
  storage_gb: number;
  api_calls_per_day: number;
}

export async function validateLicense(): Promise<License> {
  return apiFetch<License>('/billing/license');
}

export async function getUsage(): Promise<UsageStats> {
  return apiFetch<UsageStats>('/billing/usage');
}

export async function getFeatures(): Promise<Feature[]> {
  return apiFetch<Feature[]>('/billing/features');
}

export async function getLimits(): Promise<Limits> {
  return apiFetch<Limits>('/billing/limits');
}
