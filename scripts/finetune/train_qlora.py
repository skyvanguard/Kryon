"""Fase 2 — QLoRA SFT of Qwen3-8B on the converted Pentest-R1 trajectories.

Standard HF QLoRA: load the base in 4-bit (NF4), attach LoRA adapters, train
with trl's SFTTrainer over the chat-templated text (tool spec rendered in).

Smoke (validate the pipeline on a tiny model, fast):
    docker run --rm --gpus all -v <repo>/data/finetune:/data \
        -v <repo>/data/finetune/hf-cache:/root/.cache/huggingface \
        kryon-train python train_qlora.py --model Qwen/Qwen3-0.6B --max-steps 5

Real run (stop kryon-llama first to free VRAM):
    ... kryon-train python train_qlora.py --model Qwen/Qwen3-8B --epochs 1
"""

from __future__ import annotations

import argparse
import json

import torch
from datasets import load_dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3-8B")
    ap.add_argument("--data-dir", default="/data")
    ap.add_argument("--out", default="/data/adapters/qwen3-kryon")
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--max-seq-len", type=int, default=4096)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-4)
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tools = json.load(open(f"{args.data_dir}/tools.json"))

    def fmt(ex):
        return {"text": tok.apply_chat_template(ex["messages"], tools=tools, tokenize=False)}

    ds = load_dataset(
        "json",
        data_files={"train": f"{args.data_dir}/train.jsonl", "val": f"{args.data_dir}/val.jsonl"},
    )
    ds = ds.map(fmt, remove_columns=ds["train"].column_names)
    print(f"train={len(ds['train'])} val={len(ds['val'])} example_chars~{len(ds['train'][0]['text'])}")

    # bf16 throughout (Blackwell sm_120 has native bf16). bf16 needs no grad
    # scaler, avoiding the fp16-scaler-vs-bf16-grads NotImplementedError.
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.model, quantization_config=bnb, device_map="auto", torch_dtype=torch.bfloat16
    )
    model.config.use_cache = False

    lora = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_r * 2,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )

    cfg = SFTConfig(
        output_dir=args.out,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        max_steps=args.max_steps,
        num_train_epochs=args.epochs,
        max_length=args.max_seq_len,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        logging_steps=1,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        bf16=True,
        fp16=False,
        optim="paged_adamw_8bit",
        save_strategy="no",
        dataset_text_field="text",
        report_to="none",
    )
    trainer = SFTTrainer(
        model=model,
        args=cfg,
        train_dataset=ds["train"],
        eval_dataset=ds["val"],
        peft_config=lora,
        processing_class=tok,
    )
    trainer.train()
    trainer.save_model(args.out)
    free, total = torch.cuda.mem_get_info()
    print(f"DONE — adapter saved to {args.out}  | VRAM free={free / 1e9:.1f}/{total / 1e9:.1f}GB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
