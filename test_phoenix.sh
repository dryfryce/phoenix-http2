#!/bin/bash
echo "Testing Phoenix HTTP/2 Stress Testing Framework"
echo "================================================"

# Test 1: Check if phoenix-report compiles
echo -e "\n1. Testing phoenix-report library..."
cd phoenix-report
cargo build --quiet
if [ $? -eq 0 ]; then
    echo "✓ phoenix-report compiles successfully"
else
    echo "✗ phoenix-report compilation failed"
    exit 1
fi
cd ..

# Test 2: Check if phoenix-cli compiles
echo -e "\n2. Testing phoenix-cli binary..."
cd phoenix-cli
cargo build --quiet
if [ $? -eq 0 ]; then
    echo "✓ phoenix-cli compiles successfully"
else
    echo "✗ phoenix-cli compilation failed"
    exit 1
fi
cd ..

# Test 3: Run version command
echo -e "\n3. Testing version command..."
cd phoenix-cli
cargo run --quiet -- version
if [ $? -eq 0 ]; then
    echo "✓ Version command works"
else
    echo "✗ Version command failed"
fi
cd ..

# Test 4: Test report generation
echo -e "\n4. Testing report generation..."
cd phoenix-report
cargo test --quiet --lib
if [ $? -eq 0 ]; then
    echo "✓ Report tests pass"
else
    echo "✗ Report tests failed"
fi
cd ..

echo -e "\n================================================"
echo "Phoenix framework is ready for use!"
echo ""
echo "To use the CLI:"
echo "  cd phoenix-cli && cargo run -- attack rapid-reset --target https://example.com"
echo ""
echo "Available commands:"
echo "  phoenix attack <type>    - Run an attack"
echo "  phoenix scan --target <url> - Scan for vulnerabilities"
echo "  phoenix version          - Show version info"