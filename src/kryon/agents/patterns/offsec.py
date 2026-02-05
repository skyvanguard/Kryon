from kryon.repl.commands.parallel import ParallelConfig

# Pattern configuration
offsec_pattern = {
    "name": "offsec_pattern",
    "type": "parallel",
    "description": ("Bug bounty and red team with different contexts for offensive security ops"),
    "configs": [ParallelConfig("t800_infiltrator"), ParallelConfig("bug_bounter_agent")],
    "unified_context": False,
}
