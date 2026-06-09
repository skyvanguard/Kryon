# scripts/finetune — Qwen3-8B QLoRA fine-tune (local)

Implements the local SFT/QLoRA fine-tune from [`docs/FINETUNING_PLAN.md`].
Base = Qwen3-8B, compute = local RTX 5070 Ti (Blackwell sm_120, 12 GB),
emphasis = agentic discipline / anti-loop. Public datasets only.

## Fase 0 — toolchain gate (DONE ✅)

The hard gate was whether the QLoRA stack runs on Blackwell sm_120 / CUDA 13
(bitsandbytes historically lags new arches). It does:

```
docker build -f scripts/finetune/Dockerfile.train -t kryon-train .
docker run --rm --gpus all kryon-train          # runs smoke_test.py
# → gate1 fp16 matmul OK · gate2 bnb 0.49.2 Linear4bit fwd+bwd OK
#   gate3 peft LoRA over 4-bit + optim step OK · 11 GB free
```

`kryon-train` reuses the kryon runtime image (torch 2.12+cu130, validated on
sm_120) and adds the HF QLoRA stack (`requirements-finetune.txt`): bitsandbytes
+ transformers + peft + trl + datasets + accelerate. **Plain HF QLoRA, not
Unsloth** — Unsloth's Triton kernels are unproven on sm_120; evaluate later as
a speed optimization.

## Before a real training run

QLoRA of an 8B needs ~7.2 GB peak. **Stop the llama-server first** to free VRAM
(it holds ~9.5 GB while serving):

```
docker stop kryon-llama          # frees the GPU
# ... train ...
docker start kryon-llama         # restore inference
```

## Files

| File | Purpose | Status |
|------|---------|--------|
| `Dockerfile.train` | training image (kryon-train) | done |
| `requirements-finetune.txt` | HF QLoRA stack | done |
| `smoke_test.py` | Fase 0 sm_120 gate | done ✅ |
| `convert_dataset.py` | T-C-O / public sets → Kryon chat format | TODO (Fase 1) |
| `train_qlora.py` | QLoRA SFT (Qwen3-8B + LoRA via trl SFTTrainer) | TODO (Fase 2) |
| `eval_behaviour.py` | loop-rate / convergence / mode-respect + CyberGym | TODO (Fase 3) |

## Next (Fase 1 — data curation, the 80%)

1. Pull Pentest-R1 (MIT) + glaive-function-calling-v2 + ToolACE (Apache 2.0).
2. `convert_dataset.py`: T-C-O → OpenAI `tool_calls` chat format (matching
   `sdk/agents/run_to_jsonl.py`), inject STOP discipline + anti-loop pairs +
   mode-awareness → `data/finetune/{train,val}.jsonl`.
3. Decide seq length + LoRA rank from the 11 GB headroom.
