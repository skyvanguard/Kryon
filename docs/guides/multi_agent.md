# Orchestrating multiple agents

Orchestration refers to the flow of agents in your app. Which agents run, in what order, and how do they decide what happens next? There are two main ways to orchestrate agents:

1. Allowing the LLM to make decisions: this uses the intelligence of an LLM to plan, reason, and decide on what steps to take based on that.
2. Orchestrating via code: determining the flow of agents via your code.

You can mix and match these patterns. Each has their own tradeoffs, described below.

We have a number of examples in examples/kryon/agent_patterns.

#### ◉ Orchestrating via LLM

An agent is an LLM equipped with instructions, tools and handoffs. This means that given an open-ended task, the LLM can autonomously plan how it will tackle the task, using [tools](tools.md) to take actions and acquire data, and using [handoffs](handoffs.md) to delegate tasks to sub-agents. 

You could also use an agent as a tool. The agents operates independently on its provided input —without access to prior conversation history or "taking over" the conversation - completes its specific task, and returns the result to the calling (parent) agent.


#### ◉ Orchestrating via code

While orchestrating via LLM is powerful, orchestrating via code makes tasks more deterministic and predictable, in terms of speed, cost and performance. Common patterns here are:

- Using structured outputs to generate well formed data that you can inspect with your code. 

- Using a determinitstic pattern: Breaking down a task into a series of smaller steps. Chaining multiple agents, each step can be performed by an agent, and the output of one agent is used as input to the next. 

- Using [Guardrails](guardrails.md) and LLM_as_judge: They are agents that evaluates and provides feedback, until they says the inputs/outputs passes certain criteria. The agent ensures inputs/outputs are appropriate.

- Paralelization of task: Running multiple agents in parallel. This is useful for speed when you have multiple tasks that don't depend on each other.