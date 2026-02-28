import { writable } from 'svelte/store';
import type { Client } from '$lib/api/clients';
import { listClients } from '$lib/api/clients';

export const clients = writable<Client[]>([]);
export const clientsLoading = writable(false);
export const clientsError = writable<string | null>(null);

export async function loadClients() {
	clientsLoading.set(true);
	clientsError.set(null);
	try {
		const list = await listClients(0, 200);
		clients.set(list);
	} catch (e) {
		clientsError.set(e instanceof Error ? e.message : 'Failed to load clients');
	} finally {
		clientsLoading.set(false);
	}
}
