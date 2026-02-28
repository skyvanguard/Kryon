<script lang="ts">
  export let html: string;

  $: sandboxedHtml = html || '<div style="text-align:center;padding:40px;color:#9ca3af;">Esperando contenido del informe...</div>';
</script>

<div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
  <div class="px-4 py-3 border-b border-gray-700 bg-gray-950">
    <h3 class="text-sm font-semibold text-gray-300">Vista Previa del Informe</h3>
  </div>

  <div class="bg-white" style="height: 600px;">
    <iframe
      title="Report Preview"
      srcdoc={sandboxedHtml}
      sandbox="allow-same-origin"
      class="w-full h-full border-0"
    />
  </div>

  <div class="px-4 py-3 border-t border-gray-700 bg-gray-950">
    <p class="text-xs text-gray-500">
      Esta es una vista previa. El informe final puede tener diferencias menores de formato.
    </p>
  </div>
</div>
