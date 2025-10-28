"""
Main CLI interface for Skynet framework.
Provides interactive and command-line interfaces for CTF challenges.
"""
import sys
import argparse
from pathlib import Path
from typing import Optional

from ..core.config import get_config, load_config
from ..core.logging import get_logger
from ..core.agent_manager import get_agent_manager
from ..agents.recon_agent import ReconAgent
from ..agents.web_agent import WebAgent
from ..agents.crypto_agent import CryptoAgent
from ..agents.forensics_agent import ForensicsAgent
from ..agents.exploit_agent import ExploitAgent
from ..rag.retriever import get_retriever


def setup_agents():
    """Register all available agent types."""
    manager = get_agent_manager()

    # Register agent classes
    manager.register_agent_class("recon", ReconAgent)
    manager.register_agent_class("web", WebAgent)
    manager.register_agent_class("crypto", CryptoAgent)
    manager.register_agent_class("forensics", ForensicsAgent)
    manager.register_agent_class("exploit", ExploitAgent)


def cmd_run(args):
    """Run a CTF challenge with a specific agent."""
    config = get_config()
    logger = get_logger()

    logger.start_session()
    logger.info(f"Starting Skynet for {args.agent_type} challenge")

    # Setup agents
    setup_agents()
    manager = get_agent_manager()

    try:
        # Create agent
        agent_name = manager.create_agent(args.agent_type)
        agent = manager.get_agent(agent_name)

        # Prepare context
        context = {}
        if args.target:
            context['target'] = args.target
        if args.url:
            context['url'] = args.url
        if args.file:
            context['file_path'] = args.file

        # Execute task
        logger.info(f"Executing task with {agent_name}")
        response = agent.execute(args.task, context=context)

        # Display results
        print("\n" + "="*80)
        print("SKYNET ANALYSIS RESULTS")
        print("="*80)
        print(f"\nAgent: {agent_name}")
        print(f"Success: {response.success}")
        print(f"Iterations: {response.total_iterations}")
        print(f"Time: {response.execution_time:.2f}s")
        print("\n" + "-"*80)
        print("ANSWER:")
        print("-"*80)
        print(response.answer)

        if args.verbose:
            print("\n" + "-"*80)
            print("REASONING HISTORY:")
            print("-"*80)
            print(agent.get_history())

        logger.info("Task completed successfully")

    except Exception as e:
        logger.error(f"Task failed: {e}")
        print(f"\nError: {e}", file=sys.stderr)
        return 1

    finally:
        logger.end_session()

    return 0


def cmd_interactive(args):
    """Start interactive mode."""
    config = get_config()
    logger = get_logger()

    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗██╗  ██╗██╗   ██╗███╗   ██╗███████╗████████╗      ║
║   ██╔════╝██║ ██╔╝╚██╗ ██╔╝████╗  ██║██╔════╝╚══██╔══╝      ║
║   ███████╗█████╔╝  ╚████╔╝ ██╔██╗ ██║█████╗     ██║         ║
║   ╚════██║██╔═██╗   ╚██╔╝  ██║╚██╗██║██╔══╝     ██║         ║
║   ███████║██║  ██╗   ██║   ██║ ╚████║███████╗   ██║         ║
║   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝         ║
║                                                               ║
║            CTF Agent Framework with RAG                      ║
║                   Powered by Claude                          ║
╚═══════════════════════════════════════════════════════════════╝
""")

    logger.start_session()
    setup_agents()
    manager = get_agent_manager()

    print("\nAvailable agents: recon, web, crypto, forensics, exploit")
    print("Commands: /help, /stats, /exit\n")

    while True:
        try:
            user_input = input("skynet> ").strip()

            if not user_input:
                continue

            if user_input == "/exit":
                print("Goodbye!")
                break

            if user_input == "/help":
                print("""
Available Commands:
  /help       - Show this help
  /stats      - Show agent statistics
  /exit       - Exit Skynet

  <agent> <task> - Run a task with specified agent

Example:
  recon Scan 192.168.1.1 for open ports
  web Test http://example.com for SQLi
  crypto Crack hash: 5d41402abc4b2a76b9719d911017c592
  forensics Analyze file suspicious.png
""")
                continue

            if user_input == "/stats":
                stats = manager.get_statistics()
                print(f"\nAgent Statistics:")
                print(f"  Total agents: {stats['total_agents']}")
                print(f"  Total tasks: {stats['total_tasks']}")
                print(f"  Completed: {stats['completed_tasks']}")
                print(f"  Failed: {stats['failed_tasks']}")
                print(f"  Active agent: {stats['active_agent']}")
                continue

            # Parse command: <agent_type> <task>
            parts = user_input.split(maxsplit=1)
            if len(parts) < 2:
                print("Error: Invalid format. Use: <agent> <task>")
                continue

            agent_type, task = parts

            if agent_type not in ["recon", "web", "crypto", "forensics", "exploit"]:
                print(f"Error: Unknown agent type '{agent_type}'")
                continue

            # Create or get agent
            agent_name = manager.create_agent(agent_type)
            agent = manager.get_agent(agent_name)

            print(f"\n[{agent_name}] Processing...")

            # Execute task
            response = agent.execute(task)

            print(f"\n{'='*60}")
            print(f"Result (took {response.execution_time:.2f}s):")
            print('='*60)
            print(response.answer)
            print()

        except KeyboardInterrupt:
            print("\n\nUse /exit to quit")
        except Exception as e:
            logger.error(f"Error in interactive mode: {e}")
            print(f"Error: {e}")

    logger.end_session()
    return 0


def cmd_knowledge(args):
    """Manage knowledge base."""
    retriever = get_retriever()
    logger = get_logger()

    if args.action == "add":
        if args.content:
            doc_id = retriever.add_knowledge(
                content=args.content,
                category=args.category or "general",
                source=args.source or "manual"
            )
            print(f"Added knowledge with ID: {doc_id}")
        elif args.file:
            retriever.add_knowledge_from_file(
                Path(args.file),
                category=args.category or "general"
            )
            print(f"Added knowledge from {args.file}")
        elif args.directory:
            retriever.add_knowledge_from_directory(
                Path(args.directory),
                category=args.category or "general",
                pattern=args.pattern or "*.txt"
            )
            print(f"Added knowledge from {args.directory}")

    elif args.action == "search":
        results = retriever.retrieve(args.query, top_k=args.limit)
        print(f"\nFound {len(results)} results:\n")
        for i, ctx in enumerate(results, 1):
            print(f"{i}. [{ctx.metadata.get('category', 'general')}] {ctx.content[:100]}...")
            print(f"   Relevance: {ctx.relevance_score:.3f}\n")

    elif args.action == "count":
        count = retriever.count_knowledge()
        print(f"Total knowledge entries: {count}")

    elif args.action == "export":
        retriever.export_knowledge(Path(args.output))
        print(f"Exported knowledge to {args.output}")

    elif args.action == "import":
        retriever.import_knowledge(Path(args.input))
        print(f"Imported knowledge from {args.input}")

    return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Skynet - CTF Agent Framework with RAG",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Run command
    run_parser = subparsers.add_parser('run', help='Run a CTF challenge')
    run_parser.add_argument('agent_type', choices=['recon', 'web', 'crypto', 'forensics', 'exploit'],
                           help='Type of agent to use')
    run_parser.add_argument('task', help='Task description')
    run_parser.add_argument('--target', help='Target IP or hostname')
    run_parser.add_argument('--url', help='Target URL')
    run_parser.add_argument('--file', help='Target file path')
    run_parser.set_defaults(func=cmd_run)

    # Interactive command
    interactive_parser = subparsers.add_parser('interactive', help='Start interactive mode')
    interactive_parser.set_defaults(func=cmd_interactive)

    # Knowledge command
    knowledge_parser = subparsers.add_parser('knowledge', help='Manage knowledge base')
    knowledge_parser.add_argument('action', choices=['add', 'search', 'count', 'export', 'import'],
                                 help='Knowledge action')
    knowledge_parser.add_argument('--content', help='Knowledge content to add')
    knowledge_parser.add_argument('--file', help='File to add')
    knowledge_parser.add_argument('--directory', help='Directory to add')
    knowledge_parser.add_argument('--pattern', default='*.txt', help='File pattern for directory')
    knowledge_parser.add_argument('--category', help='Knowledge category')
    knowledge_parser.add_argument('--source', help='Knowledge source')
    knowledge_parser.add_argument('--query', help='Search query')
    knowledge_parser.add_argument('--limit', type=int, default=5, help='Search result limit')
    knowledge_parser.add_argument('--output', help='Export output file')
    knowledge_parser.add_argument('--input', help='Import input file')
    knowledge_parser.set_defaults(func=cmd_knowledge)

    # Parse arguments
    args = parser.parse_args()

    # Load config if specified
    if args.config:
        load_config(args.config)

    # Set verbose if specified
    if args.verbose:
        config = get_config()
        config.verbose = True

    # Execute command
    if hasattr(args, 'func'):
        return args.func(args)
    else:
        # Default to interactive mode
        args.func = cmd_interactive
        return cmd_interactive(args)


if __name__ == "__main__":
    sys.exit(main())
