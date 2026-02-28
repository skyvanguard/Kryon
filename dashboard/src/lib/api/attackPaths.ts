import { apiFetch } from './client';

export interface AttackPathNode {
  id: string;
  type: 'asset' | 'vulnerability' | 'exploit';
  label: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  metadata?: Record<string, unknown>;
}

export interface AttackPathEdge {
  from: string;
  to: string;
  technique?: string;
  confidence: number;
}

export interface AttackPath {
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  risk_score: number;
  length: number;
}

export interface KillChainStep {
  phase: string;
  technique: string;
  mitre_id: string;
  description: string;
}

export interface KillChain {
  chain_id: string;
  target: string;
  steps: KillChainStep[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  feasibility: number;
}

export async function analyzeAttackPaths(): Promise<AttackPath[]> {
  return apiFetch<AttackPath[]>('/attack-paths/analyze', {
    method: 'POST'
  });
}

export async function getClientAttackPaths(clientId: string): Promise<AttackPath[]> {
  return apiFetch<AttackPath[]>(`/attack-paths/clients/${clientId}`);
}

export async function getClientChains(clientId: string): Promise<KillChain[]> {
  return apiFetch<KillChain[]>(`/attack-paths/clients/${clientId}/chains`);
}
