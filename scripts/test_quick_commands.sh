#!/bin/bash
# Test script for Skynet quick commands

echo "🧪 Testing Skynet Quick Commands"
echo "=================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

test_command() {
    local desc="$1"
    local cmd="$2"

    echo -e "${BLUE}Testing: $desc${NC}"
    echo "Command: $cmd"

    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASSED${NC}"
    else
        echo -e "${RED}❌ FAILED${NC}"
    fi
    echo ""
}

# Test basic imports
echo "1️⃣  Testing Python imports..."
python3 -c "from skynet.core.config import get_config; print('✅ Config OK')"
python3 -c "from skynet.core.logging import get_logger; print('✅ Logging OK')"
python3 -c "from skynet.core.executor import CommandExecutor; print('✅ Executor OK')"
python3 -c "from skynet.core.flag_detector import get_flag_detector; print('✅ Flag Detector OK')"
echo ""

# Test quick command help
echo "2️⃣  Testing quick command interface..."
python3 -m skynet.cli.quick 2>&1 | head -5
echo ""

# Test flag detector
echo "3️⃣  Testing flag detection..."
python3 << 'EOF'
from skynet.core.flag_detector import detect_flags_in_output

test_outputs = [
    "The flag is HTB{test_flag_123}",
    "flag{another_test}",
    "Found hash: 5d41402abc4b2a76b9719d911017c592"
]

for output in test_outputs:
    flags = detect_flags_in_output(output, "test")
    if flags:
        print(f"✅ Detected: {flags[0].value}")
    else:
        print(f"❌ No flag detected in: {output[:30]}")
EOF
echo ""

# Test tools (if available)
echo "4️⃣  Testing tool availability..."
command -v nmap >/dev/null 2>&1 && echo "✅ nmap installed" || echo "⚠️  nmap not found"
command -v gobuster >/dev/null 2>&1 && echo "✅ gobuster installed" || echo "⚠️  gobuster not found"
command -v john >/dev/null 2>&1 && echo "✅ john installed" || echo "⚠️  john not found"
command -v binwalk >/dev/null 2>&1 && echo "✅ binwalk installed" || echo "⚠️  binwalk not found"
echo ""

echo "=================================="
echo "🎉 Basic tests complete!"
echo ""
echo "💡 Next steps:"
echo "   1. Install missing security tools if needed"
echo "   2. Run: python scripts/init_knowledge.py"
echo "   3. Try: python -m skynet.cli.quick search 'test'"
