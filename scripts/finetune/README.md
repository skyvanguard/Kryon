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
| `convert_dataset.py` | T-C-O → Kryon `run_command` tool-call chat format + STOP turn | **done** (Pentest-R1) |
| `train_qlora.py` | QLoRA SFT (Qwen3-8B + LoRA via trl SFTTrainer) | **smoke ✅** |
| `eval_behaviour.py` | loop-rate / convergence / mode-respect + CyberGym | TODO (Fase 3) |

### Fase 2 smoke (validated end-to-end on sm_120)

```
# free the GPU first — an 8B QLoRA at seq 2048 uses the WHOLE 12 GB
docker stop kryon-llama
R=$(pwd)
docker run --rm --gpus all -v $R/data/finetune:/data \
  -v $R/data/finetune/hf-cache:/root/.cache/huggingface \
  -v $R/scripts/finetune:/train kryon-train \
  python /train/train_qlora.py --model Qwen/Qwen3-8B --max-steps 5 --max-seq-len 2048 --grad-accum 1
docker start kryon-llama
# → loss 2.11→1.25, token_acc 0.68→0.75, ~3.8 s/step, adapter saved.
```

**Memory note:** Qwen3-8B QLoRA at `--max-seq-len 2048` fills all 12 GB
(VRAM free 0.0 GB at peak). For the real run, keep seq ≤ 2048 (truncate long
trajectories) or add flash-attention-2 to cut activation memory; **the
llama-server MUST be stopped** (it holds ~9.5 GB). bf16 throughout — fp16's
grad scaler errors on bf16 grads here.

## Fase 1 — data curation (in progress)

Pentest-R1 (MIT) is converted and template-validated:

```
git clone --depth 1 https://github.com/KHenryAegis/Pentest-R1 data/finetune/pentest-r1
python scripts/finetune/convert_dataset.py --steps data/finetune/pentest-r1/data/steps --out data/finetune
# → 532 walkthroughs → train.jsonl (479) + val.jsonl (53) + tools.json
#   avg 57.8 turns/example; Qwen3 apply_chat_template renders the tool_calls OK
```

Each `command` maps to a `run_command` tool_call; the `thought` is the
assistant's reasoning content; a final **STOP turn** teaches convergence
(anti-loop). Datasets live under `data/finetune/` (gitignored).

Remaining Fase 1: glaive-fc-v2 + ToolACE (tool-format), Primus (cyber CoT),
synthetic anti-loop negatives, mode-awareness (passive vs active) examples;
then decide seq length + LoRA rank from the 11 GB headroom.
