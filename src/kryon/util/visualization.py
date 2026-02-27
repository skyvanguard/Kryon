"""
Visualization utilities for KRYON.

This module provides functions for visualizing agent graphs and relationships.
"""

from rich.console import Console
from rich.tree import Tree


def visualize_agent_graph(start_agent):
    """
    Visualize agent graph showing all bidirectional connections between agents.
    Uses Rich library for pretty printing.
    """
    console = Console()
    if start_agent is None:
        console.print("[red]No agent provided to visualize.[/red]")
        return

    tree = Tree(f"🤖 {start_agent.name} (Current Agent)", guide_style="bold blue")

    visited = set()
    agent_nodes = {}
    agent_positions = {}
    position_counter = 0

    def add_agent_node(agent, parent=None, is_transfer=False):
        """Add an agent node and track for cross-connections."""
        nonlocal position_counter
        if agent is None:
            return None
        aid = id(agent)
        if aid in visited:
            if is_transfer and parent:
                original_pos = agent_positions.get(aid)
                parent.add(f"[cyan]↩ Return to {agent.name} (Agent #{original_pos})[/cyan]")
            return agent_nodes.get(aid)

        visited.add(aid)
        position_counter += 1
        agent_positions[aid] = position_counter

        if is_transfer and parent:
            node = parent
        elif parent:
            node = parent.add(f"[green]{agent.name} (#{position_counter})[/green]")
        else:
            node = tree
        agent_nodes[aid] = node

        # Add tools
        tools_node = node.add("[yellow]Tools[/yellow]")

        # Get all tools from the agent
        all_tools = getattr(agent, "tools", [])

        # Import necessary modules for MCP checking
        from kryon.repl.commands.mcp import get_mcp_tools_for_agent

        # Separate regular tools from MCP tools
        regular_tools = []
        mcp_tools = []

        # Get the agent's name for MCP association lookup
        agent_name = getattr(agent, "name", "")

        # Get MCP tools from the associations
        try:
            associated_mcp_tools = get_mcp_tools_for_agent(agent_name)
            mcp_tool_names = {tool.name for tool in associated_mcp_tools}
        except Exception:
            mcp_tool_names = set()

        # Categorize tools
        for tool in all_tools:
            tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "")
            # Check if this tool is an MCP tool by checking if it's in the MCP associations
            # or if it has certain MCP-related attributes
            if tool_name in mcp_tool_names or (hasattr(tool, "_is_mcp_tool") and tool._is_mcp_tool):
                mcp_tools.append(tool)
            else:
                regular_tools.append(tool)

        # Show regular tools first
        for tool in regular_tools:
            tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "")
            tools_node.add(f"[blue]{tool_name}[/blue]")

        # Show MCP tools with a different color/prefix
        if mcp_tools:
            for tool in mcp_tools:
                tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "")
                tools_node.add(f"[magenta]🔌 {tool_name}[/magenta]")

        # Add a summary line if we have both types
        if regular_tools and mcp_tools:
            summary_text = f"[dim]({len(regular_tools)} regular, {len(mcp_tools)} MCP tools)[/dim]"
            tools_node.add(summary_text)
        elif mcp_tools and not regular_tools:
            summary_text = f"[dim]({len(mcp_tools)} MCP tools)[/dim]"
            tools_node.add(summary_text)
        elif regular_tools and not mcp_tools:
            summary_text = f"[dim]({len(regular_tools)} regular tools)[/dim]"
            tools_node.add(summary_text)
        elif not regular_tools and not mcp_tools:
            tools_node.add("[dim](No tools)[/dim]")

        # Add handoffs
        transfers_node = node.add("[magenta]Handoffs[/magenta]")

        # First, handle old-style handoffs through handoffs list
        for handoff_fn in getattr(agent, "handoffs", []):
            if callable(handoff_fn) and not hasattr(handoff_fn, "agent_name"):
                try:
                    next_agent = handoff_fn()
                    if next_agent:
                        transfer_node = transfers_node.add(f"🤖 {next_agent.name}")
                        add_agent_node(next_agent, transfer_node, True)
                except Exception:
                    continue
            elif hasattr(handoff_fn, "agent_name"):
                # Handle SDK handoff objects
                try:
                    handoff_name = handoff_fn.agent_name
                    # Find the actual agent instance if available
                    next_agent = None

                    # Try to find the agent by name in the global namespace
                    # This is a heuristic and might not always work
                    import sys

                    for module_name, module in sys.modules.items():
                        if module_name.startswith("kryon.agents"):
                            agent_var_name = handoff_name.lower().replace(" ", "_") + "_agent"
                            if hasattr(module, agent_var_name):
                                next_agent = getattr(module, agent_var_name)
                                break

                    if next_agent:
                        transfer_node = transfers_node.add(
                            f"🤖 {handoff_name} via {handoff_fn.tool_name}"
                        )
                        add_agent_node(next_agent, transfer_node, True)
                    else:
                        # If we can't find the agent, just show the name
                        handoff_text = f"🤖 {handoff_name} via {handoff_fn.tool_name}"
                        transfers_node.add(f"[yellow]{handoff_text}[/yellow]")
                except Exception as e:
                    transfers_node.add(f"[red]Error: {str(e)}[/red]")
            elif isinstance(handoff_fn, dict) and "agent_name" in handoff_fn:
                # Handle dictionary handoff objects
                handoff_name = handoff_fn["agent_name"]
                tool_name = handoff_fn.get("tool_name", f"transfer_to_{handoff_name}")
                transfers_node.add(f"[yellow]🤖 {handoff_name} via {tool_name}[/yellow]")

        return node

    # Start traversal from the root agent
    add_agent_node(start_agent)
    console.print(tree)
