import { writable } from 'svelte/store';

export interface Toast {
	id: string;
	type: 'error' | 'success' | 'warning' | 'info';
	message: string;
	duration: number;
}

const _DURATIONS: Record<Toast['type'], number> = {
	error: 6000,
	success: 3000,
	warning: 5000,
	info: 4000
};

function createToastStore() {
	const { subscribe, update } = writable<Toast[]>([]);

	let _counter = 0;

	function add(type: Toast['type'], message: string) {
		const id = `toast-${++_counter}`;
		const duration = _DURATIONS[type];
		const toast: Toast = { id, type, message, duration };

		update((toasts) => [...toasts, toast]);

		setTimeout(() => {
			remove(id);
		}, duration);

		return id;
	}

	function remove(id: string) {
		update((toasts) => toasts.filter((t) => t.id !== id));
	}

	return {
		subscribe,
		error: (message: string) => add('error', message),
		success: (message: string) => add('success', message),
		warning: (message: string) => add('warning', message),
		info: (message: string) => add('info', message),
		remove
	};
}

export const toast = createToastStore();
