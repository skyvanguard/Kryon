"""
Agent management module for Skynet framework.
Handles agent orchestration, coordination, and delegation.
"""
from typing import Dict, List, Optional, Any, Type
from dataclasses import dataclass, field
from enum import Enum
import time

from .config import get_config
from .logging import get_logger


class AgentStatus(Enum):
    """Status of an agent."""
    IDLE = "idle"
    THINKING = "thinking"
    ACTING = "acting"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentTask:
    """Represents a task for an agent."""
    task_id: str
    description: str
    agent_type: str
    priority: int = 0
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    status: AgentStatus = AgentStatus.IDLE
    result: Optional[Any] = None
    error: Optional[str] = None


class AgentManager:
    """
    Manages multiple agents and coordinates their activities.
    Implements agent handoff and delegation patterns.
    """

    def __init__(self):
        self.config = get_config()
        self.logger = get_logger()
        self.agents: Dict[str, Any] = {}  # agent_name -> agent_instance
        self.agent_classes: Dict[str, Type] = {}  # agent_type -> agent_class
        self.tasks: Dict[str, AgentTask] = {}  # task_id -> task
        self.active_agent: Optional[str] = None
        self.task_counter: int = 0

    def register_agent_class(self, agent_type: str, agent_class: Type):
        """Register an agent class for later instantiation."""
        self.agent_classes[agent_type] = agent_class
        self.logger.info(f"Registered agent class: {agent_type}")

    def create_agent(self, agent_type: str, agent_name: Optional[str] = None) -> str:
        """
        Create a new agent instance.

        Args:
            agent_type: Type of agent to create
            agent_name: Optional custom name for the agent

        Returns:
            Agent name
        """
        if agent_type not in self.agent_classes:
            raise ValueError(f"Unknown agent type: {agent_type}")

        if agent_name is None:
            agent_name = f"{agent_type}_{len(self.agents)}"

        agent_class = self.agent_classes[agent_type]
        agent_instance = agent_class(name=agent_name)

        self.agents[agent_name] = agent_instance
        self.logger.info(f"Created agent: {agent_name} (type: {agent_type})")

        return agent_name

    def get_agent(self, agent_name: str) -> Optional[Any]:
        """Get an agent by name."""
        return self.agents.get(agent_name)

    def remove_agent(self, agent_name: str):
        """Remove an agent."""
        if agent_name in self.agents:
            del self.agents[agent_name]
            self.logger.info(f"Removed agent: {agent_name}")

    def create_task(
        self,
        description: str,
        agent_type: str,
        priority: int = 0,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new task.

        Args:
            description: Task description
            agent_type: Type of agent to handle this task
            priority: Task priority (higher = more important)
            context: Additional context for the task

        Returns:
            Task ID
        """
        self.task_counter += 1
        task_id = f"task_{self.task_counter}"

        task = AgentTask(
            task_id=task_id,
            description=description,
            agent_type=agent_type,
            priority=priority,
            context=context or {}
        )

        self.tasks[task_id] = task
        self.logger.info(f"Created task {task_id}: {description}")

        return task_id

    def assign_task(self, task_id: str, agent_name: str):
        """Assign a task to a specific agent."""
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")

        if agent_name not in self.agents:
            raise ValueError(f"Unknown agent: {agent_name}")

        task = self.tasks[task_id]
        self.logger.info(f"Assigning task {task_id} to agent {agent_name}")

        task.status = AgentStatus.THINKING
        self.active_agent = agent_name

    def execute_task(self, task_id: str, auto_create_agent: bool = True) -> Any:
        """
        Execute a task, optionally creating an agent if needed.

        Args:
            task_id: ID of the task to execute
            auto_create_agent: Whether to automatically create an agent if needed

        Returns:
            Task result
        """
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")

        task = self.tasks[task_id]

        # Find or create an agent for this task
        agent_name = None
        for name, agent in self.agents.items():
            if agent.agent_type == task.agent_type and agent.status == AgentStatus.IDLE:
                agent_name = name
                break

        if agent_name is None and auto_create_agent:
            agent_name = self.create_agent(task.agent_type)

        if agent_name is None:
            raise RuntimeError(f"No available agent for task type: {task.agent_type}")

        # Assign and execute
        self.assign_task(task_id, agent_name)
        agent = self.agents[agent_name]

        try:
            self.logger.info(f"Executing task {task_id} with agent {agent_name}")
            task.status = AgentStatus.ACTING

            result = agent.execute(task.description, context=task.context)

            task.result = result
            task.status = AgentStatus.COMPLETED
            self.logger.info(f"Task {task_id} completed successfully")

            return result

        except Exception as e:
            task.status = AgentStatus.FAILED
            task.error = str(e)
            self.logger.error(f"Task {task_id} failed: {e}")
            raise

        finally:
            self.active_agent = None

    def handoff_task(
        self,
        from_agent: str,
        to_agent_type: str,
        description: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Handoff a task from one agent to another.

        Args:
            from_agent: Name of the agent handing off
            to_agent_type: Type of agent to hand off to
            description: Description of the new task
            context: Context to pass to the new agent

        Returns:
            New task ID
        """
        self.logger.info(f"Handoff from {from_agent} to {to_agent_type}: {description}")

        # Create new task
        task_id = self.create_task(
            description=description,
            agent_type=to_agent_type,
            context=context or {}
        )

        return task_id

    def get_task_status(self, task_id: str) -> AgentStatus:
        """Get the status of a task."""
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")
        return self.tasks[task_id].status

    def get_task_result(self, task_id: str) -> Any:
        """Get the result of a completed task."""
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")

        task = self.tasks[task_id]
        if task.status != AgentStatus.COMPLETED:
            raise RuntimeError(f"Task {task_id} is not completed yet")

        return task.result

    def list_agents(self) -> List[str]:
        """List all registered agents."""
        return list(self.agents.keys())

    def list_tasks(self, status: Optional[AgentStatus] = None) -> List[str]:
        """List all tasks, optionally filtered by status."""
        if status is None:
            return list(self.tasks.keys())
        return [
            task_id for task_id, task in self.tasks.items()
            if task.status == status
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about agents and tasks."""
        return {
            "total_agents": len(self.agents),
            "total_tasks": len(self.tasks),
            "completed_tasks": len(self.list_tasks(AgentStatus.COMPLETED)),
            "failed_tasks": len(self.list_tasks(AgentStatus.FAILED)),
            "active_agent": self.active_agent,
            "agent_types": list(self.agent_classes.keys())
        }


# Global agent manager instance
_agent_manager: Optional[AgentManager] = None


def get_agent_manager() -> AgentManager:
    """Get or create the global agent manager instance."""
    global _agent_manager
    if _agent_manager is None:
        _agent_manager = AgentManager()
    return _agent_manager
