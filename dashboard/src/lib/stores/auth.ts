/** Authentication stores for the dashboard. */

import { writable, derived } from 'svelte/store';

export interface AuthUser {
	id: string;
	username: string;
	email: string;
	role: string;
	is_active: boolean;
}

export const accessToken = writable<string | null>(
	typeof localStorage !== 'undefined' ? localStorage.getItem('kryon_token') : null
);

export const currentUser = writable<AuthUser | null>(null);

export const isAuthenticated = derived(accessToken, ($token) => !!$token);

// Persist token to localStorage
accessToken.subscribe((token) => {
	if (typeof localStorage !== 'undefined') {
		if (token) {
			localStorage.setItem('kryon_token', token);
		} else {
			localStorage.removeItem('kryon_token');
		}
	}
});

export function setAuth(token: string, user: AuthUser) {
	accessToken.set(token);
	currentUser.set(user);
}

export function clearAuth() {
	accessToken.set(null);
	currentUser.set(null);
}
