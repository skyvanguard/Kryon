import { apiFetch } from './client';

export interface OnboardingSession {
  id: number;
  current_step: number;
  data: Record<string, unknown>;
  completed: boolean;
  created_at: string;
}

export interface Credential {
  id: number;
  type: 'ssh' | 'api_key' | 'password' | 'certificate';
  label: string;
  data: Record<string, unknown>;
  created_at: string;
}

export interface AssetImport {
  identifier: string;
  type: string;
  criticality: string;
  metadata?: Record<string, unknown>;
}

export interface ScopeValidation {
  target: string;
  reachable: boolean;
  response_time_ms: number | null;
  error: string | null;
}

export async function startOnboarding(): Promise<OnboardingSession> {
  return apiFetch<OnboardingSession>('/onboarding/start', {
    method: 'POST'
  });
}

export async function updateStep(
  sessionId: number,
  step: number,
  data: Record<string, unknown>
): Promise<OnboardingSession> {
  return apiFetch<OnboardingSession>(`/onboarding/${sessionId}/step/${step}`, {
    method: 'PUT',
    body: JSON.stringify(data)
  });
}

export async function getSession(sessionId: number): Promise<OnboardingSession> {
  return apiFetch<OnboardingSession>(`/onboarding/${sessionId}`);
}

export async function completeOnboarding(sessionId: number): Promise<void> {
  return apiFetch<void>(`/onboarding/${sessionId}/complete`, {
    method: 'POST'
  });
}

export async function saveCredential(data: Omit<Credential, 'id' | 'created_at'>): Promise<Credential> {
  return apiFetch<Credential>('/onboarding/credentials', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

export async function listCredentials(): Promise<Credential[]> {
  return apiFetch<Credential[]>('/onboarding/credentials');
}

export async function deleteCredential(id: number): Promise<void> {
  return apiFetch<void>(`/onboarding/credentials/${id}`, {
    method: 'DELETE'
  });
}

export async function importAssets(assets: AssetImport[]): Promise<{ imported: number }> {
  return apiFetch<{ imported: number }>('/onboarding/assets/import', {
    method: 'POST',
    body: JSON.stringify({ assets })
  });
}

export async function validateScope(targets: string[]): Promise<ScopeValidation[]> {
  return apiFetch<ScopeValidation[]>('/onboarding/scope/validate', {
    method: 'POST',
    body: JSON.stringify({ targets })
  });
}
