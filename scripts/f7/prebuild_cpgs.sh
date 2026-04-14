#!/usr/bin/env bash
# F7.4 batch pre-parse. One CPG per Juliet test file (which contains
# bad + goodG2B + goodB2G). Run once; cached in /tmp/f7-cpgs.
set -euo pipefail

JULIET=/workspace/.juliet/juliet-test-suite-c/testcases
OUT=/tmp/f7-cpgs
JOERN=/tmp/joern/joern-cli
mkdir -p "$OUT"

CASES=(
  "CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01.c"
  "CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_02.c"
  "CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_03.c"
  "CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_04.c"
  "CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_05.c"
  "CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__char_fscanf_add_01.c"
  "CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__char_fscanf_add_02.c"
  "CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__char_fscanf_add_03.c"
  "CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__char_fscanf_add_04.c"
  "CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__char_fscanf_add_05.c"
)

for rel in "${CASES[@]}"; do
  name=$(basename "$rel" .c)
  cpg="$OUT/${name}.cpg"
  if [[ -f "$cpg" ]]; then
    echo "[skip] $name (already parsed)"
    continue
  fi
  # joern-parse wants a directory, so stage the single file
  stage="$OUT/stage_$name"
  mkdir -p "$stage"
  cp "$JULIET/$rel" "$stage/"
  echo "[parse] $name"
  "$JOERN/joern-parse" "$stage" --output "$cpg" 2>&1 | tail -2
  rm -rf "$stage"
done

echo "---"
ls -lh "$OUT"/*.cpg
