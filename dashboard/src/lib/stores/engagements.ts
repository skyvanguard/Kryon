/** Engagement stores. */

import { writable, derived } from 'svelte/store';
import type { Engagement, EngagementDetail } from '$lib/api/engagements';
import { listEngagements } from '$lib/api/engagements';

export const engagements = writable<Engagement[]>([]);
export const currentEngagement = writable<EngagementDetail | null>(null);
export const engagementLogs = writable<string[]>([]);

export const activeEngagements = derived(engagements, ($e) =>
	$e.filter((e) => ['active', 'planning'].includes(e.status))
);

export const completedEngagements = derived(engagements, ($e) =>
	$e.filter((e) => ['completed', 'failed', 'cancelled'].includes(e.status))
);

export async function loadEngagements() {
	try {
		const list = await listEngagements();
		engagements.set(list);
	} catch {
		/* API not available */
	}
}
