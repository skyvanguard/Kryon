"""
Module for executing Python code and capturing its output.
"""

import io
import sys

from kryon.sdk.agents import function_tool


@function_tool
def execute_python_code(code: str, context: dict = None) -> str:
    """
    Execute Python code and return the output.

    Args:
        code (str): Python code to execute
        context (Dict, optional): Additional context for execution

    Returns:
        str: Output from code execution
    """
    try:
        local_vars = {}
        if context:
            local_vars.update(context)

        # Capture output using StringIO
        stdout = io.StringIO()
        sys.stdout = stdout

        safe_globals = {"__builtins__": {
            "print": print, "len": len, "range": range, "str": str,
            "int": int, "float": float, "list": list, "dict": dict,
            "tuple": tuple, "set": set, "bool": bool, "type": type,
            "enumerate": enumerate, "zip": zip, "map": map, "filter": filter,
            "sorted": sorted, "reversed": reversed, "sum": sum, "min": min, "max": max,
            "abs": abs, "round": round, "isinstance": isinstance,
            "True": True, "False": False, "None": None,
        }}
        try:
            # Execute code with restricted builtins
            # nosec B102 # pylint: disable=exec-used
            exec(code, safe_globals, local_vars)  # nosec 102  # nosemgrep: exec-detected
        finally:
            # Always restore stdout even if exec raises
            sys.stdout = sys.__stdout__

        output = stdout.getvalue()

        # Return captured output or last expression value
        return output if output else str(local_vars.get("__builtins__", {}).get("_", None))

    except Exception as e:  # pylint: disable=broad-except
        return f"Error executing code: {str(e)}"
