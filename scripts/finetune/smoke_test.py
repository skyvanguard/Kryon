"""Fase 0 gate — prove the QLoRA toolchain runs on this Blackwell sm_120 GPU.

If every check passes, the local QLoRA plan is viable as written. If the
bitsandbytes 4-bit checks fail, the plan must pivot (FP16 LoRA on shorter
sequences, or cloud GPU).

Run inside the training image with the GPU attached:
    docker run --rm --gpus all kryon-train
"""

from __future__ import annotations

import sys


def main() -> int:
    import torch

    print(f"torch={torch.__version__}  cuda_available={torch.cuda.is_available()}")
    if not torch.cuda.is_available():
        print("FAIL: no CUDA device visible")
        return 1

    cap = torch.cuda.get_device_capability(0)
    print(f"device={torch.cuda.get_device_name(0)}  capability=sm_{cap[0]}{cap[1]}")

    # Gate 1 — plain fp16 matmul on the GPU (sm_120 codegen).
    x = torch.randn(2048, 2048, device="cuda", dtype=torch.float16)
    _ = (x @ x).sum().item()
    print("gate1 fp16 matmul on GPU: OK")

    # Gate 2 — bitsandbytes 4-bit forward + backward (the QLoRA-critical path).
    import bitsandbytes as bnb
    from bitsandbytes.nn import Linear4bit

    print(f"bitsandbytes={bnb.__version__}")
    lin = Linear4bit(1024, 1024, bias=False, compute_dtype=torch.float16).cuda()
    inp = torch.randn(8, 1024, device="cuda", dtype=torch.float16, requires_grad=True)
    out = lin(inp)
    out.sum().backward()
    torch.cuda.synchronize()
    assert inp.grad is not None, "no gradient flowed through Linear4bit"
    print(f"gate2 bnb Linear4bit fwd+bwd on sm_{cap[0]}{cap[1]}: OK  out={tuple(out.shape)}")

    # Gate 3 — peft LoRA wraps a 4-bit module and a step runs.
    import torch.nn as nn
    from peft import LoraConfig, get_peft_model

    class _Tiny(nn.Module):
        def __init__(self):
            super().__init__()
            self.proj = Linear4bit(1024, 1024, bias=False, compute_dtype=torch.float16)
            self.head = nn.Linear(1024, 16).half()

        def forward(self, z):
            return self.head(self.proj(z))

    model = _Tiny().cuda()
    cfg = LoraConfig(r=8, lora_alpha=16, target_modules=["proj"], lora_dropout=0.0, bias="none")
    model = get_peft_model(model, cfg)
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=1e-4)
    z = torch.randn(8, 1024, device="cuda", dtype=torch.float16)
    loss = model(z).float().pow(2).mean()
    loss.backward()
    opt.step()
    torch.cuda.synchronize()
    print(f"gate3 peft LoRA over 4-bit, optimizer step: OK  loss={loss.item():.4f}")

    free, total = torch.cuda.mem_get_info()
    print(f"VRAM free={free / 1e9:.1f}GB / total={total / 1e9:.1f}GB")
    print("\n✅ ALL GATES PASSED — local QLoRA toolchain works on this GPU.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
