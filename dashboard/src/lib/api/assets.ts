import { apiFetch } from './client';

export interface Asset {
	id: string;
	client_id: string;
	asset_type: string;
	identifier: string;
	status: string;
	metadata_json: string;
	first_seen: string;
	last_seen: string;
}

export interface AssetChange {
	id: string;
	asset_id: string;
	change_type: string;
	old_value: string;
	new_value: string;
	detected_at: string;
	scan_id: string;
}

export async function listAssets(
	offset = 0,
	limit = 50,
	query = '',
	asset_type = '',
	client_id = ''
): Promise<{ items: Asset[]; total: number }> {
	const params = new URLSearchParams();
	params.set('offset', offset.toString());
	params.set('limit', limit.toString());
	if (query) params.set('query', query);
	if (asset_type) params.set('asset_type', asset_type);
	if (client_id) params.set('client_id', client_id);
	return apiFetch(`/assets?${params}`);
}

export async function getAsset(id: string): Promise<Asset> {
	return apiFetch(`/assets/${id}`);
}

export async function getAssetTimeline(id: string): Promise<{ asset_id: string; changes: AssetChange[] }> {
	return apiFetch(`/assets/${id}/timeline`);
}

export async function createAsset(data: Partial<Asset>): Promise<{ id: string }> {
	return apiFetch('/assets', {
		method: 'POST',
		body: JSON.stringify(data)
	});
}
