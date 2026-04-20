"""Bug-bounty platform integrations (HackerOne, Bugcrowd, Intigriti, ...).

Each platform wraps its public API as @function_tools with a uniform
contract: scope-enforced pentest, findings auto-indexed into the F64
pattern library, reports submittable with request_approval guard.
"""
