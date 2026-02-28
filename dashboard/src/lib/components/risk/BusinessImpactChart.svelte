<script lang="ts">
  export let impact: {
    data_breach: number;
    service_disruption: number;
    regulatory: number;
    reputational: number;
  };

  const impacts = [
    { key: 'data_breach', label: 'Filtración de Datos', value: impact.data_breach, color: 'bg-red-500' },
    { key: 'service_disruption', label: 'Interrupción de Servicio', value: impact.service_disruption, color: 'bg-orange-500' },
    { key: 'regulatory', label: 'Regulatorio', value: impact.regulatory, color: 'bg-yellow-500' },
    { key: 'reputational', label: 'Reputacional', value: impact.reputational, color: 'bg-purple-500' }
  ];

  $: maxValue = Math.max(...impacts.map(i => i.value));
</script>

<div class="space-y-4">
  <h3 class="text-lg font-semibold text-gray-300">Impacto de Negocio</h3>

  <div class="space-y-3">
    {#each impacts as item}
      <div>
        <div class="flex justify-between items-center mb-1">
          <span class="text-sm text-gray-400">{item.label}</span>
          <span class="text-sm font-semibold text-gray-300">{item.value}%</span>
        </div>
        <div class="w-full bg-gray-800 rounded-full h-3 overflow-hidden">
          <div
            class="{item.color} h-full rounded-full transition-all duration-500"
            style="width: {(item.value / maxValue) * 100}%"
          ></div>
        </div>
      </div>
    {/each}
  </div>

  <div class="mt-4 p-3 bg-gray-800 rounded-lg">
    <p class="text-xs text-gray-500">
      Estos valores representan el impacto potencial en el negocio basado en los hallazgos de seguridad actuales.
    </p>
  </div>
</div>
