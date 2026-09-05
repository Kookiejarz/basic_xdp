# BPF Verifier Variant Report

测量日期：2026-09-01

本报告记录 TCP accounting 优化实验的可复现结果。所有数值来自 Docker
Linux 环境中的真实 BPF verifier load，不是离线指令估算。

## Environment

| 项目 | 值 |
| --- | --- |
| Docker image | `xdpbuild:tools` |
| Kernel | `7.0.12-linuxkit` |
| Architecture | `aarch64` |
| clang | `Ubuntu clang version 18.1.3 (1ubuntu1)` |
| bpftool | `v7.4.0` |
| libbpf | `v1.4` |
| verifier timeout | 90 seconds per variant |

## Results

`static_insns` 是所有 loaded BPF subprogram 的 code size 总和；其余字段来自
verifier summary。

| Variant | Status | Static | Processed | Max states/insn | Total states | Peak states | Verify time (usec) | Stack |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | passed | 13481 | 282798 | 27 | 11892 | 4610 | 1556784 | 288 |
| shared-inline | passed | 13273 | 255442 | 20 | 11492 | 4420 | 1367501 | 288 |
| shared-static-subprog | passed | 11393 | 259940 | 20 | 11695 | 4536 | 1330792 | 288 |
| shared-global-subprog | verifier_failed | - | - | - | - | - | - | - |
| no-l3 | passed | 11787 | 222688 | 22 | 10411 | 3651 | 1131976 | 280 |
| no-l4 | passed | 10400 | 185965 | 22 | 8792 | 3307 | 888841 | 280 |
| no-l5 | passed | 12020 | 227967 | 22 | 10758 | 3791 | 1212698 | 280 |
| no-accounting | passed | 6920 | 124823 | 20 | 7102 | 2048 | 583829 | 256 |
| family-split | passed | 13447 | 279987 | 27 | 11830 | 4578 | 1592266 | 304 |
| accounting-static-subprog | passed | 12141 | 677592 | 20 | 25230 | 7259 | 3853823 | 296 |
| accounting-global-subprog | verifier_failed | - | - | - | - | - | - | - |

原始 TSV 快照：`reproducible-tests/verifier-variants.tsv`

## Variant Flags

| Variant | Compiler flags |
| --- | --- |
| baseline | none |
| shared-inline | `-DAUTO_XDP_SHARED_CONN_UPDATE_MODE=1` |
| shared-static-subprog | `-DAUTO_XDP_SHARED_CONN_UPDATE_MODE=2` |
| shared-global-subprog | `-DAUTO_XDP_SHARED_CONN_UPDATE_MODE=3` |
| no-l3 | `-DAUTO_XDP_TCP_ACCOUNT_L3=0` |
| no-l4 | `-DAUTO_XDP_TCP_ACCOUNT_L4=0` |
| no-l5 | `-DAUTO_XDP_TCP_ACCOUNT_L5=0` |
| no-accounting | `-DAUTO_XDP_TCP_ACCOUNT_L3=0 -DAUTO_XDP_TCP_ACCOUNT_L4=0 -DAUTO_XDP_TCP_ACCOUNT_L5=0` |
| family-split | `-DAUTO_XDP_TCP_ACCOUNT_FAMILY_SPLIT=1` |
| accounting-static-subprog | `-DAUTO_XDP_TCP_ACCOUNTING_MODE=1` |
| accounting-global-subprog | `-DAUTO_XDP_TCP_ACCOUNTING_MODE=2` |

## Findings

1. `no-l4` 是单层关闭中收益最大的变体：相对 baseline，processed instructions
   从 `282798` 降到 `185965`，total states 从 `11892` 降到 `8792`。
2. `shared-inline` 和 `shared-static-subprog` 都通过 verifier；static subprog
   将 static count 降到 `11393`，但 processed/state 的收益有限。
3. `family-split` 只将 static count 降低 `34`，processed instructions 降低
   `2811`，但 stack 从 `288` 增加到 `304`，verification time 也略有增加。
4. `accounting-static-subprog` 虽将主程序拆出 accounting path，但 total states
   增至 `25230`，peak states 增至 `7259`，processed instructions 增至 `677592`，
   不建议采用。
5. 两个 global subprog 变体在该 kernel 上失败。verifier 报告调用 global 函数
   时 map-value pointer 被视为 `mem_or_null`，最终出现：
   `R1 invalid mem access 'mem_or_null'`。

## Exact Reproduction

宿主机需要 Docker Desktop/Linux Docker 和 `--privileged` 权限。下面命令使用
`reproducible-tests/source/` 中保存的完整实验源码快照作为 `/workspace`，因此在
生产源码恢复后仍可直接复现：

```bash
docker run --rm --privileged \
  -v "$PWD/reproducible-tests/source:/workspace" \
  -w /workspace \
  xdpbuild:tools \
  bash -lc 'set -Eeuo pipefail; \
    mkdir -p /sys/fs/bpf; \
    mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; \
    VERIFIER_VARIANT_TIMEOUT_SECONDS=90 \
    VERIFIER_VARIANTS_FILE=/workspace/verifier-variants.tsv \
    VERIFIER_VARIANTS_LOG_DIR=/workspace/verifier-variants-logs \
    bash tests/bash/measure_verifier_variants.sh'
```

测量脚本的独立副本位于：`verifier-variants-reproduce.sh`。
完整可运行源码快照位于：`reproducible-tests/source/`。
快照中的测量脚本与独立副本应保持一致，可用以下命令确认：

```bash
diff -u verifier-variants-reproduce.sh reproducible-tests/source/tests/bash/measure_verifier_variants.sh
```

只测指定变体时，可以增加 `VERIFIER_VARIANTS`，例如：

```bash
docker run --rm --privileged \
  -v "$PWD/reproducible-tests/source:/workspace" \
  -w /workspace \
  xdpbuild:tools \
  bash -lc 'set -Eeuo pipefail; \
    mkdir -p /sys/fs/bpf; \
    mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; \
    VERIFIER_VARIANTS=baseline,no-l4 \
    VERIFIER_VARIANT_TIMEOUT_SECONDS=90 \
    bash tests/bash/measure_verifier_variants.sh'
```

脚本会对成功变体保留 compact summary；compile/verifier 失败的变体保留完整
日志到 `verifier-variants-logs/`，以便检查 verifier 原文。
