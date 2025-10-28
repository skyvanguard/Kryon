"""
Base agent class for Skynet framework.
Implements ReAct pattern (Reasoning + Acting) for CTF challenges.
"""
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from enum import Enum
import time

from ..core.config import get_config
from ..core.logging import get_logger
from ..core.executor import CommandExecutor, ExecutionResult
from ..core.agent_manager import AgentStatus
from ..rag.retriever import get_retriever, RetrievedContext


class StepType(Enum):
    """Type of reasoning step."""
    THOUGHT = "thought"
    ACTION = "action"
    OBSERVATION = "observation"
    ANSWER = "answer"


@dataclass
class ReasoningStep:
    """Represents a step in the agent's reasoning process."""
    step_type: StepType
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResponse:
    """Response from an agent execution."""
    success: bool
    answer: str
    reasoning_steps: List[ReasoningStep]
    total_iterations: int
    execution_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    """
    Abstract base class for all Skynet agents.
    Implements the ReAct pattern for iterative problem solving.
    """

    def __init__(
        self,
        name: str,
        agent_type: str,
        description: str,
        system_prompt: Optional[str] = None
    ):
        self.name = name
        self.agent_type = agent_type
        self.description = description
        self.system_prompt = system_prompt or self._default_system_prompt()

        self.config = get_config()
        self.logger = get_logger()
        self.executor = CommandExecutor()
        self.retriever = get_retriever()

        self.status = AgentStatus.IDLE
        self.reasoning_steps: List[ReasoningStep] = []
        self.current_iteration = 0

    @abstractmethod
    def _default_system_prompt(self) -> str:
        """Get the default system prompt for this agent type."""
        pass

    @abstractmethod
    def _get_available_tools(self) -> List[Dict[str, Any]]:
        """
        Get the list of tools available to this agent.

        Returns:
            List of tool definitions with name, description, and parameters
        """
        pass

    def _add_step(self, step_type: StepType, content: str, metadata: Optional[Dict] = None):
        """Add a reasoning step to the history."""
        step = ReasoningStep(
            step_type=step_type,
            content=content,
            metadata=metadata or {}
        )
        self.reasoning_steps.append(step)
        self.logger.log_agent_action(self.name, step_type.value, {"content": content})

    def _think(self, thought: str):
        """Record a thought/reasoning step."""
        self._add_step(StepType.THOUGHT, thought)

    def _act(self, action: str, tool_name: str) -> str:
        """
        Execute an action using a tool.

        Args:
            action: Description of the action
            tool_name: Name of the tool to use

        Returns:
            Observation from the action
        """
        self._add_step(StepType.ACTION, f"Using {tool_name}: {action}")

        # Execute the tool
        observation = self._execute_tool(tool_name, action)

        self._add_step(StepType.OBSERVATION, observation)
        return observation

    def _execute_tool(self, tool_name: str, action: str) -> str:
        """
        Execute a specific tool.

        Args:
            tool_name: Name of the tool
            action: Tool-specific action/command

        Returns:
            Tool output as string
        """
        try:
            # Special handling for common tools
            if tool_name == "execute_command":
                result = self.executor.execute(action)
                self.logger.log_tool_use(self.name, tool_name, action, result.stdout)

                if result.success:
                    return f"Command executed successfully:\n{result.stdout}"
                else:
                    return f"Command failed (exit code {result.exit_code}):\n{result.stderr}"

            elif tool_name == "search_knowledge":
                contexts = self.retriever.retrieve(action, top_k=3)
                self.logger.log_tool_use(self.name, tool_name, action, f"{len(contexts)} results")

                if contexts:
                    return "\n\n".join([f"- {ctx.content}" for ctx in contexts])
                else:
                    return "No relevant knowledge found."

            elif tool_name == "read_file":
                from pathlib import Path
                file_path = Path(action)
                if file_path.exists():
                    content = file_path.read_text()
                    self.logger.log_tool_use(self.name, tool_name, action, f"{len(content)} bytes")
                    return content
                else:
                    return f"File not found: {action}"

            elif tool_name == "write_file":
                # Expects format: "path|content"
                parts = action.split("|", 1)
                if len(parts) == 2:
                    from pathlib import Path
                    file_path = Path(parts[0])
                    content = parts[1]
                    file_path.write_text(content)
                    self.logger.log_tool_use(self.name, tool_name, parts[0], "written")
                    return f"File written successfully: {parts[0]}"
                else:
                    return "Invalid format. Use: path|content"

            else:
                # Try to execute as a custom tool method
                method_name = f"_tool_{tool_name}"
                if hasattr(self, method_name):
                    method = getattr(self, method_name)
                    result = method(action)
                    self.logger.log_tool_use(self.name, tool_name, action, result)
                    return result
                else:
                    return f"Unknown tool: {tool_name}"

        except Exception as e:
            self.logger.log_error(self.name, e, {"tool": tool_name, "action": action})
            return f"Tool execution failed: {str(e)}"

    def _augment_with_context(self, query: str) -> str:
        """
        Augment the query with relevant context from RAG.

        Args:
            query: Original query

        Returns:
            Augmented query with context
        """
        contexts = self.retriever.retrieve(
            query=query,
            top_k=self.config.top_k_results,
            category=self.agent_type
        )

        if not contexts:
            return query

        context_text = self.retriever.format_context(contexts)
        augmented = f"{context_text}\n\n## Current Task:\n{query}"

        return augmented

    def execute(self, task: str, context: Optional[Dict[str, Any]] = None) -> AgentResponse:
        """
        Execute a task using the ReAct pattern.

        Args:
            task: Task description
            context: Optional additional context

        Returns:
            AgentResponse with results
        """
        start_time = time.time()
        self.status = AgentStatus.THINKING
        self.reasoning_steps = []
        self.current_iteration = 0

        self.logger.info(f"[{self.name}] Starting task: {task}")

        try:
            # Augment task with RAG context
            augmented_task = self._augment_with_context(task)

            # Execute the agent's specific logic
            answer = self._solve(augmented_task, context or {})

            self._add_step(StepType.ANSWER, answer)

            execution_time = time.time() - start_time
            self.status = AgentStatus.COMPLETED

            self.logger.info(f"[{self.name}] Task completed in {execution_time:.2f}s")

            return AgentResponse(
                success=True,
                answer=answer,
                reasoning_steps=self.reasoning_steps,
                total_iterations=self.current_iteration,
                execution_time=execution_time,
                metadata={"agent_type": self.agent_type}
            )

        except Exception as e:
            self.logger.log_error(self.name, e)
            self.status = AgentStatus.FAILED

            execution_time = time.time() - start_time

            return AgentResponse(
                success=False,
                answer=f"Task failed: {str(e)}",
                reasoning_steps=self.reasoning_steps,
                total_iterations=self.current_iteration,
                execution_time=execution_time,
                metadata={"agent_type": self.agent_type, "error": str(e)}
            )

    @abstractmethod
    def _solve(self, task: str, context: Dict[str, Any]) -> str:
        """
        Solve the task using agent-specific logic.
        This is where the ReAct loop is implemented.

        Args:
            task: Task description (possibly augmented with context)
            context: Additional context

        Returns:
            Final answer
        """
        pass

    def reset(self):
        """Reset the agent state."""
        self.reasoning_steps = []
        self.current_iteration = 0
        self.status = AgentStatus.IDLE
        self.logger.debug(f"[{self.name}] Agent reset")

    def get_history(self) -> str:
        """Get formatted reasoning history."""
        history = []
        for step in self.reasoning_steps:
            history.append(f"[{step.step_type.value.upper()}] {step.content}")
        return "\n\n".join(history)

    def summarize(self) -> str:
        """Get a summary of the agent's current state."""
        return f"""
Agent: {self.name}
Type: {self.agent_type}
Status: {self.status.value}
Iterations: {self.current_iteration}
Steps: {len(self.reasoning_steps)}
Description: {self.description}
        """.strip()
