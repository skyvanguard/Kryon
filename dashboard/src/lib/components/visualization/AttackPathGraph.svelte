<script lang="ts">
  import { onMount } from 'svelte';
  import type { AttackPathNode, AttackPathEdge } from '$lib/api/attackPaths';

  export let nodes: AttackPathNode[] = [];
  export let edges: AttackPathEdge[] = [];

  let svg: SVGSVGElement;
  let width = 800;
  let height = 600;

  onMount(async () => {
    if (nodes.length === 0) return;

    const d3 = await import('d3');

    const simulation = d3
      .forceSimulation(nodes as any)
      .force(
        'link',
        d3
          .forceLink(edges)
          .id((d: any) => d.id)
          .distance(100)
      )
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(30));

    const svgElement = d3.select(svg);
    svgElement.selectAll('*').remove();

    const g = svgElement.append('g');

    // Zoom behavior
    const zoom = d3.zoom().on('zoom', (event) => {
      g.attr('transform', event.transform);
    });
    svgElement.call(zoom as any);

    // Draw edges
    const link = g
      .append('g')
      .selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke', '#4b5563')
      .attr('stroke-width', 2)
      .attr('marker-end', 'url(#arrowhead)');

    // Arrow marker
    svgElement
      .append('defs')
      .append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '-0 -5 10 10')
      .attr('refX', 25)
      .attr('refY', 0)
      .attr('orient', 'auto')
      .attr('markerWidth', 8)
      .attr('markerHeight', 8)
      .append('path')
      .attr('d', 'M 0,-5 L 10,0 L 0,5')
      .attr('fill', '#4b5563');

    // Node color based on severity
    function getNodeColor(node: AttackPathNode) {
      if (node.type === 'vulnerability') {
        switch (node.severity) {
          case 'critical':
            return '#dc2626';
          case 'high':
            return '#ea580c';
          case 'medium':
            return '#eab308';
          case 'low':
            return '#22c55e';
          default:
            return '#6b7280';
        }
      }
      if (node.type === 'asset') return '#06b6d4';
      return '#8b5cf6';
    }

    // Draw nodes
    const node = g
      .append('g')
      .selectAll('circle')
      .data(nodes)
      .join('circle')
      .attr('r', 15)
      .attr('fill', (d: any) => getNodeColor(d))
      .attr('stroke', '#1f2937')
      .attr('stroke-width', 2)
      .style('cursor', 'pointer')
      .call(
        d3
          .drag()
          .on('start', dragstarted)
          .on('drag', dragged)
          .on('end', dragended) as any
      );

    // Node labels
    const label = g
      .append('g')
      .selectAll('text')
      .data(nodes)
      .join('text')
      .text((d: any) => d.label)
      .attr('font-size', 10)
      .attr('fill', '#d1d5db')
      .attr('text-anchor', 'middle')
      .attr('dy', 30)
      .style('pointer-events', 'none');

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node.attr('cx', (d: any) => d.x).attr('cy', (d: any) => d.y);

      label.attr('x', (d: any) => d.x).attr('y', (d: any) => d.y);
    });

    function dragstarted(event: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }

    function dragged(event: any) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }

    function dragended(event: any) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }

    return () => {
      simulation.stop();
    };
  });
</script>

<div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
  <div class="p-4 border-b border-gray-700">
    <h3 class="text-lg font-semibold text-gray-300">Grafo de Rutas de Ataque</h3>
    <p class="text-sm text-gray-500 mt-1">
      {nodes.length} nodos, {edges.length} conexiones. Arrastra para reorganizar, zoom con scroll.
    </p>
  </div>

  <div class="bg-gray-950 flex items-center justify-center" style="height: {height}px">
    {#if nodes.length === 0}
      <p class="text-gray-500">No hay datos de rutas de ataque.</p>
    {:else}
      <svg bind:this={svg} {width} {height} class="w-full h-full" />
    {/if}
  </div>

  <div class="p-4 border-t border-gray-700 flex gap-4 text-xs">
    <div class="flex items-center gap-2">
      <div class="w-3 h-3 rounded-full bg-[#06b6d4]"></div>
      <span class="text-gray-400">Activo</span>
    </div>
    <div class="flex items-center gap-2">
      <div class="w-3 h-3 rounded-full bg-[#dc2626]"></div>
      <span class="text-gray-400">Vulnerabilidad</span>
    </div>
    <div class="flex items-center gap-2">
      <div class="w-3 h-3 rounded-full bg-[#8b5cf6]"></div>
      <span class="text-gray-400">Exploit</span>
    </div>
  </div>
</div>
