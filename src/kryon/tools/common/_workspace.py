"""Workspace directory resolution utilities."""

import os

from wasabi import color


def _get_workspace_dir() -> str:
    """Determines the target workspace directory based on env vars for host."""
    base_dir_env = os.getenv("KRYON_WORKSPACE_DIR")
    workspace_name = os.getenv("KRYON_WORKSPACE")

    # Determine the base directory
    if base_dir_env:
        base_dir = os.path.abspath(base_dir_env)
    else:  # Default base directory is 'workspaces'
        if workspace_name:
            base_dir = os.path.join(os.getcwd(), "workspaces")
        else:  # If no workspace name is set, the workspace IS the CWD.
            return os.getcwd()

    # If a workspace name is provided, append it to the base directory
    if workspace_name:
        if not all(c.isalnum() or c in ["_", "-"] for c in workspace_name):
            print(
                color(
                    f"Invalid KRYON_WORKSPACE name '{workspace_name}'. Using directory '{base_dir}' instead.",
                    fg="yellow",
                )
            )
            target_dir = base_dir
        else:
            target_dir = os.path.join(base_dir, workspace_name)
    else:
        target_dir = base_dir

    # Ensure the final target directory exists on the host
    try:
        abs_target_dir = os.path.abspath(target_dir)
        os.makedirs(abs_target_dir, exist_ok=True)
        return abs_target_dir
    except OSError as e:
        print(
            color(
                f"Error creating/accessing host workspace directory '{abs_target_dir}': {e}",
                fg="red",
            )
        )
        print(color(f"Falling back to current directory: {os.getcwd()}", fg="yellow"))
        return os.getcwd()


def _get_container_workspace_path() -> str:
    """Determines the target workspace path inside the container."""
    workspace_name = os.getenv("KRYON_WORKSPACE")
    if workspace_name:
        if not all(c.isalnum() or c in ["_", "-"] for c in workspace_name):
            print(
                color(
                    f"Invalid KRYON_WORKSPACE name '{workspace_name}' for container. Using '/workspace'.",
                    fg="yellow",
                )
            )
            return "/"
        # Standard path inside KRYON containers
        return f"/workspace/workspaces/{workspace_name}"
    else:
        return "/"
