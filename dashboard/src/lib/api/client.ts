/** Base API client with auth support (API key + JWT). */

import { get } from 'svelte/store';
import { accessToken, clearAuth, setAuth, type AuthUser } from '$lib/stores/auth';

const BASE_URL = '/api/v1';

let apiKey: string | null = null;

export function setApiKey(key: string) {
	apiKey = key;
}

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
	const headers: Record<string, string> = {
		'Content-Type': 'application/json',
		...(options.headers as Record<string, string> || {})
	};

	// Prefer JWT token, fall back to API key
	const token = get(accessToken);
	if (token) {
		headers['Authorization'] = `Bearer ${token}`;
	} else if (apiKey) {
		headers['X-API-Key'] = apiKey;
	}

	const resp = await fetch(`${BASE_URL}${path}`, {
		...options,
		headers
	});

	// Auto-redirect on 401
	if (resp.status === 401) {
		clearAuth();
		if (typeof window !== 'undefined' && !path.startsWith('/auth/')) {
			window.location.href = '/login';
		}
		throw new Error('Authentication required');
	}

	if (!resp.ok) {
		const body = await resp.json().catch(() => ({ detail: resp.statusText }));
		throw new Error(body.detail || `API error: ${resp.status}`);
	}

	return resp.json();
}

/** Login and store the JWT token. */
export async function login(username: string, password: string): Promise<AuthUser> {
	const data = await apiFetch<{
		access_token: string;
		refresh_token: string;
		user: AuthUser;
	}>('/auth/login', {
		method: 'POST',
		body: JSON.stringify({ username, password })
	});

	setAuth(data.access_token, data.user);

	// Store refresh token
	if (typeof localStorage !== 'undefined') {
		localStorage.setItem('kryon_refresh', data.refresh_token);
	}

	return data.user;
}

/** Refresh the access token using the stored refresh token. */
export async function refreshAccessToken(): Promise<boolean> {
	const refreshToken = typeof localStorage !== 'undefined'
		? localStorage.getItem('kryon_refresh')
		: null;

	if (!refreshToken) return false;

	try {
		const data = await apiFetch<{ access_token: string }>('/auth/refresh', {
			method: 'POST',
			body: JSON.stringify({ refresh_token: refreshToken })
		});
		accessToken.set(data.access_token);
		return true;
	} catch {
		clearAuth();
		return false;
	}
}

/** Logout — clear all auth state. */
export function logout() {
	clearAuth();
	if (typeof localStorage !== 'undefined') {
		localStorage.removeItem('kryon_refresh');
	}
	if (typeof window !== 'undefined') {
		window.location.href = '/login';
	}
}
