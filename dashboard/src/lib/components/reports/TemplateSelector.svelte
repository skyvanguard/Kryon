<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let selectedTemplate = 'executive';

  const dispatch = createEventDispatcher();

  const templates = [
    {
      id: 'military',
      name: 'Militar',
      description: 'Informe táctico detallado con TTPs, cadenas de muerte y análisis forense.',
      icon: '🎖️',
      features: ['Kill Chains', 'Análisis MITRE ATT&CK', 'Rutas de Ataque', 'IOCs']
    },
    {
      id: 'executive',
      name: 'Ejecutivo',
      description: 'Resumen de alto nivel enfocado en impacto de negocio y riesgos.',
      icon: '💼',
      features: ['Resumen Ejecutivo', 'Métricas de Riesgo', 'Impacto Financiero', 'Recomendaciones']
    },
    {
      id: 'technical',
      name: 'Técnico',
      description: 'Informe detallado para equipos técnicos con evidencias y exploits.',
      icon: '🔧',
      features: ['Evidencias Detalladas', 'Pasos de Reproducción', 'Código PoC', 'Remediation']
    },
    {
      id: 'compliance',
      name: 'Cumplimiento',
      description: 'Mapeo de hallazgos a frameworks (PCI-DSS, SOC2, ISO27001).',
      icon: '📋',
      features: ['Mapeo a Frameworks', 'Gap Analysis', 'Control Testing', 'Auditoría']
    }
  ];

  function selectTemplate(id: string) {
    selectedTemplate = id;
    dispatch('select', id);
  }
</script>

<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
  {#each templates as template}
    <button
      type="button"
      on:click={() => selectTemplate(template.id)}
      class="text-left p-4 rounded-lg border-2 transition-all {selectedTemplate === template.id
        ? 'border-kryon-500 bg-kryon-900/20'
        : 'border-gray-700 bg-gray-900 hover:border-gray-600'}"
    >
      <div class="flex items-start gap-3">
        <div class="text-3xl">{template.icon}</div>
        <div class="flex-1">
          <h3 class="text-lg font-semibold text-gray-300 mb-1">{template.name}</h3>
          <p class="text-sm text-gray-500 mb-3">{template.description}</p>
          <ul class="space-y-1">
            {#each template.features as feature}
              <li class="flex items-center gap-2 text-xs text-gray-400">
                <svg class="w-3 h-3 text-kryon-500" fill="currentColor" viewBox="0 0 20 20">
                  <path
                    fill-rule="evenodd"
                    d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                    clip-rule="evenodd"
                  />
                </svg>
                {feature}
              </li>
            {/each}
          </ul>
        </div>
      </div>
    </button>
  {/each}
</div>
