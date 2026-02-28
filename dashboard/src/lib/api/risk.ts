import { apiFetch } from './client';

export interface RiskOverview {
  overall_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  business_impact: {
    data_breach: number;
    service_disruption: number;
    regulatory: number;
    reputational: number;
  };
  trend_30d: number;
}

export interface RiskyAsset {
  identifier: string;
  asset_type: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  exposure_score: number;
  risk_score: number;
  findings_count: number;
  critical_findings: number;
}

export interface RiskTrend {
  date: string;
  risk_score: number;
}

export async function getRiskOverview(clientId?: string): Promise<RiskOverview> {
  const params = clientId ? `?client_id=${clientId}` : '';
  return apiFetch<RiskOverview>(`/risk/overview${params}`);
}

export async function getRiskyAssets(clientId?: string, limit = 20): Promise<RiskyAsset[]> {
  const params = new URLSearchParams();
  if (clientId) params.set('client_id', clientId);
  params.set('limit', limit.toString());

  return apiFetch<RiskyAsset[]>(`/risk/assets?${params}`);
}

export async function getRiskTrend(clientId?: string, days = 30): Promise<RiskTrend[]> {
  const params = new URLSearchParams();
  if (clientId) params.set('client_id', clientId);
  params.set('days', days.toString());

  return apiFetch<RiskTrend[]>(`/risk/trend?${params}`);
}
