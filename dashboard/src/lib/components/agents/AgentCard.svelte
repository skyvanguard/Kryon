<script lang="ts">
	import type { AgentSummary } from '$lib/api/agents';

	export let agent: AgentSummary;

	const iconMap: Record<string, string> = {
		pentest: '🗡️',
		recon: '🔍',
		vuln: '🐛',
		network: '🌐',
		memory: '🧠',
		reverse: '⚙️',
		mobile: '📱',
		forensic: '🔬',
		wireless: '📡',
		chrome: '🌍',
		mail: '📧',
		ctf: '🏁',
		guardian: '🛡️',
		reporter: '📋',
		signal: '📻',
		strategic: '🎯',
		central: '🖥️',
		rf: '📶',
		code: '💻',
		retester: '🔄',
		mission: '📊',
	};

	function getIcon(key: string): string {
		for (const [keyword, icon] of Object.entries(iconMap)) {
			if (key.includes(keyword)) return icon;
		}
		return '🤖';
	}

	$: icon = getIcon(agent.key);
</script>

<a
	href="/agents/{agent.key}"
	class="group block bg-gray-800/50 border border-gray-700/50 rounded-xl p-5 hover:border-kryon-500/60 hover:bg-gray-800 transition-all duration-200"
>
	<div class="flex items-start gap-3">
		<span class="text-2xl mt-0.5">{icon}</span>
		<div class="flex-1 min-w-0">
			<h3 class="text-kryon-400 font-semibold group-hover:text-kryon-300 transition-colors truncate">
				{agent.name}
			</h3>
			<p class="text-gray-400 text-sm mt-1 line-clamp-2 leading-relaxed">
				{agent.description || 'No description'}
			</p>
		</div>
	</div>
</a>
