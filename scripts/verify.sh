#!/usr/bin/env bash
# 全量测试门禁：**失败即非零退出**。
#
# 起因：曾用
#     cargo test 2>&1 | grep "test result" | awk '{s+=$4}'
# 只累加 passed 数，从不看 failed —— 于是「21 passed; 1 failed」被读成
# 「测试通过: 21」，漏掉了 CI 才会报出的失败。
# 本脚本改为解析 failed/ignored 并据此退出码，杜绝「看着过了其实没过」。
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_INCREMENTAL=0

out=$(cargo test 2>&1)
echo "$out" | grep -E "^(error|warning: unused)" -A5 || true

# 逐个测试二进制汇总 passed / failed
summary=$(echo "$out" | grep -E "^test result:" || true)
if [ -z "$summary" ]; then
  echo "!! 没有捕获到任何 test result —— 构建可能失败"
  echo "$out" | tail -30
  exit 1
fi
echo "$summary"

failed=$(echo "$summary" | awk '{ for(i=1;i<=NF;i++) if($i=="failed;") { gsub(";", "", $(i-1)); s+=$(i-1) } } END { print s+0 }')
ignored=$(echo "$summary" | awk '{ for(i=1;i<=NF;i++) if($i=="ignored;") { gsub(";", "", $(i-1)); s+=$(i-1) } } END { print s+0 }')
passed=$(echo "$summary" | awk '{ for(i=1;i<=NF;i++) if($i=="passed;") { gsub(";", "", $(i-1)); s+=$(i-1) } } END { print s+0 }')

if echo "$out" | grep -qE "FAILED|panicked at|error\[E"; then
  echo
  echo "==== 失败详情 ===="
  echo "$out" | grep -E "FAILED|panicked at|^---- .* stdout" -A4 | head -60
fi

echo
if [ "$failed" -ne 0 ] || [ "$ignored" -ne 0 ]; then
  echo "❌ 测试未全绿：passed=$passed failed=$failed ignored=$ignored"
  exit 1
fi
echo "✅ 测试全绿：passed=$passed"
