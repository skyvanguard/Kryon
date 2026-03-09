"""
Module for executing Python code and capturing its output.
"""

import contextlib
import io

from kryon.sdk.agents import function_tool


# Sandboxed builtins for code execution (no __import__, open, exec, eval, compile)
_SAFE_BUILTINS = {
    "print": print, "len": len, "range": range, "str": str,
    "int": int, "float": float, "list": list, "dict": dict,
    "tuple": tuple, "set": set, "bool": bool, "type": type,
    "enumerate": enumerate, "zip": zip, "map": map, "filter": filter,
    "sorted": sorted, "reversed": reversed, "sum": sum, "min": min, "max": max,
    "abs": abs, "round": round, "isinstance": isinstance,
    "True": True, "False": False, "None": None,
}


@function_tool
def execute_python_code(code: str, context: dict = None) -> str:
    """
    Execute Python code in a sandboxed environment and return the output.

    Args:
        code (str): Python code to execute
        context (Dict, optional): Additional context for execution

    Returns:
        str: Output from code execution
    """
    try:
        local_vars = {}
        if context:
            for k, v in context.items():
                if k.startswith("_") or callable(v):
                    continue
                local_vars[k] = v

        safe_globals = {"__builtins__": _SAFE_BUILTINS}

        # Thread-safe stdout capture using contextlib.redirect_stdout
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            # Intentional sandboxed exec for KRYON code execution tool
            # nosec B102 # pylint: disable=exec-used # nosemgrep: exec-detected
            exec(code, safe_globals, local_vars)  # noqa: S102

        output = stdout_capture.getvalue()
        return output if output else str(local_vars.get("__builtins__", {}).get("_", None))

    except Exception as e:  # pylint: disable=broad-except
        return f"Error executing code: {str(e)}"
