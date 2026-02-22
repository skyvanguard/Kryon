from kryon.repl.commands.parallel import ParallelConfig

# Pattern configuration
offsec_pattern = {
    "name": "offsec_pattern",
    "type": "parallel",
    "description": ("Bug bounty and red team with different contexts for offensive security ops"),
    "configs": [ParallelConfig("pentest_agent"), ParallelConfig("vuln_hunter")],
    "unified_context": False,
}
