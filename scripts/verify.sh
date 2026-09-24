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

# 前端门禁（先跑，失败即快速退出，不白等整套 cargo test）：
#  1) `node --check`：语法层错误；
#  2) `ui-smoke.js`：用最小 DOM 桩**真的执行** app.js 并逐页驱动。
# console_tests 只能做「文本里包含某字符串」的断言，拦不住
# 「语法合法但 IIFE 提前闭合 → 加载期 ReferenceError」这类 bug —— 实测
# `node --check` 也拦不住（语法是合法的），只有真执行才拦得住。
# node 不存在时跳过（不把 node 做成构建依赖）。
if command -v node >/dev/null 2>&1; then
  if node --check assets/app.js; then
    echo "✅ app.js 语法检查通过"
  else
    echo "❌ app.js 语法检查失败"
    exit 1
  fi
  node scripts/ui-smoke.js || exit 1
else
  echo "（跳过前端语法 / UI 冒烟：未安装 node）"
fi

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
