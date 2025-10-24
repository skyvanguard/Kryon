# Configuration

## Environment Variables

CAI leverages the `.env` file to load configuration at launch. To facilitate the setup, the repo provides an exemplary [`.env.example`](.env.example) file provides a template for configuring CAI's setup and your LLM API keys to work with desired LLM models.

⚠️  Important:

CAI does NOT provide API keys for any model by default. Don't ask us to provide keys, use your own or host your own models.

⚠️  Note:

The OPENAI_API_KEY must not be left blank. It should contain either "sk-123" (as a placeholder) or your actual API key. See https://github.com/aliasrobotics/cai/issues/27.

### List of Environment Variables

| Variable | Description |
|----------|-------------|
| CTF_NAME | Name of the CTF challenge to run (e.g. "picoctf_static_flag") |
| CTF_CHALLENGE | Specific challenge name within the CTF to test |
| CTF_SUBNET | Network subnet for the CTF container |
| CTF_IP | IP address for the CTF container |
| CTF_INSIDE | Whether to conquer the CTF from within container |
| CAI_MODEL | Model to use for agents |
| CAI_DEBUG | Set debug output level (0: Only tool outputs, 1: Verbose debug output, 2: CLI debug output) |
| CAI_BRIEF | Enable/disable brief output mode |
| CAI_MAX_TURNS | Maximum number of turns for agent interactions |
| CAI_TRACING | Enable/disable OpenTelemetry tracing |
| CAI_AGENT_TYPE | Specify the agents to use (boot2root, one_tool...) |
| CAI_STATE | Enable/disable stateful mode |
| CAI_MEMORY | Enable/disable memory mode (episodic, semantic, all) |
| CAI_MEMORY_ONLINE | Enable/disable online memory mode |
| CAI_MEMORY_OFFLINE | Enable/disable offline memory |
| CAI_ENV_CONTEXT | Add dirs and current env to llm context |
| CAI_MEMORY_ONLINE_INTERVAL | Number of turns between online memory updates |
| CAI_PRICE_LIMIT | Price limit for the conversation in dollars |
| CAI_REPORT | Enable/disable reporter mode (ctf, nis2, pentesting) |
| CAI_SUPPORT_MODEL | Model to use for the support agent |
| CAI_SUPPORT_INTERVAL | Number of turns between support agent executions |
| CAI_WORKSPACE | Defines the name of the workspace |
| CAI_WORKSPACE_DIR | Specifies the directory path where the workspace is located |

## Custom OpenAI Base URL Support

CAI supports configuring a custom OpenAI API base URL via the `OPENAI_BASE_URL` environment variable. This allows users to redirect API calls to a custom endpoint, such as a proxy or self-hosted OpenAI-compatible service.

Example `.env` entry configuration:
```
OLLAMA_API_BASE="https://custom-openai-proxy.com/v1"
```

Or directly from the command line:
```bash
OLLAMA_API_BASE="https://custom-openai-proxy.com/v1" cai
```

## OpenRouter Integration

The Cybersecurity AI (CAI) platform offers seamless integration with OpenRouter, a unified interface for Large Language Models (LLMs). This integration is crucial for users who wish to leverage advanced AI capabilities in their cybersecurity tasks. OpenRouter acts as a bridge, allowing CAI to communicate with various LLMs, thereby enhancing the flexibility and power of the AI agents used within CAI.

To enable OpenRouter support in CAI, you need to configure your environment by adding specific entries to your `.env` file. This setup ensures that CAI can interact with the OpenRouter API, facilitating the use of sophisticated models like Meta-LLaMA. Here's how you can configure it:

```bash
CAI_AGENT_TYPE=redteam_agent
CAI_MODEL=openrouter/meta-llama/llama-4-maverick
OPENROUTER_API_KEY=<sk-your-key>  # note, add yours
OPENROUTER_API_BASE=https://openrouter.ai/api/v1
``` 