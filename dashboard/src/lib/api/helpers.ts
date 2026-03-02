import { toast } from '$lib/stores/toast';

/**
 * Execute an async API call with automatic error toast on failure.
 */
export async function withToast<T>(
	fn: () => Promise<T>,
	errorMsg = 'Operation failed'
): Promise<T | null> {
	try {
		return await fn();
	} catch (err) {
		const detail = err instanceof Error ? err.message : String(err);
		toast.error(`${errorMsg}: ${detail}`);
		return null;
	}
}

/**
 * Execute an async API call with success + error toast feedback.
 */
export async function withToastFeedback<T>(
	fn: () => Promise<T>,
	successMsg: string,
	errorMsg = 'Operation failed'
): Promise<T | null> {
	try {
		const result = await fn();
		toast.success(successMsg);
		return result;
	} catch (err) {
		const detail = err instanceof Error ? err.message : String(err);
		toast.error(`${errorMsg}: ${detail}`);
		return null;
	}
}
