<script lang="ts">
  export let score: number;

  $: percentage = Math.min(100, Math.max(0, score));
  $: rotation = (percentage / 100) * 180 - 90;
  $: color =
    percentage >= 80 ? '#ef4444' :
    percentage >= 60 ? '#f59e0b' :
    percentage >= 40 ? '#eab308' :
    '#22c55e';
</script>

<div class="flex flex-col items-center">
  <svg viewBox="0 0 200 120" class="w-full max-w-sm">
    <!-- Background arc -->
    <path
      d="M 20 100 A 80 80 0 0 1 180 100"
      fill="none"
      stroke="#374151"
      stroke-width="20"
      stroke-linecap="round"
    />

    <!-- Colored arc -->
    <path
      d="M 20 100 A 80 80 0 0 1 180 100"
      fill="none"
      stroke={color}
      stroke-width="20"
      stroke-linecap="round"
      stroke-dasharray="251.2"
      stroke-dashoffset={251.2 - (percentage / 100) * 251.2}
      class="transition-all duration-500"
    />

    <!-- Needle -->
    <line
      x1="100"
      y1="100"
      x2="100"
      y2="30"
      stroke="#9ca3af"
      stroke-width="3"
      stroke-linecap="round"
      transform="rotate({rotation} 100 100)"
      class="transition-transform duration-500"
    />

    <!-- Center circle -->
    <circle cx="100" cy="100" r="8" fill="#1f2937" />
    <circle cx="100" cy="100" r="5" fill={color} />

    <!-- Score text -->
    <text
      x="100"
      y="95"
      text-anchor="middle"
      class="text-3xl font-bold"
      fill="#d1d5db"
    >
      {score}
    </text>
  </svg>

  <div class="mt-2 text-center">
    <p class="text-sm text-gray-500">Puntuación de Riesgo</p>
    <p class="text-lg font-semibold" style="color: {color}">
      {percentage >= 80 ? 'Crítico' :
       percentage >= 60 ? 'Alto' :
       percentage >= 40 ? 'Medio' :
       'Bajo'}
    </p>
  </div>
</div>
