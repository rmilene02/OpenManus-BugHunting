#!/bin/bash

# OpenManus-BugHunting Demo Script
# This script demonstrates the platform capabilities in environments
# where security tools may not be installed

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║              OpenManus-BugHunting Demo Mode                   ║"
echo "║                                                               ║"
echo "║   This demo simulates tool availability for demonstration     ║"
echo "║   purposes when security tools are not installed.            ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Set demo mode environment variable
export OPENMANUS_DEMO_MODE=true

echo "🔧 Demo mode enabled - simulating tool availability"
echo "🎯 Running reconnaissance scan on example.com"
echo

# Run the reconnaissance scan
python main.py --target example.com --mode reconnaissance --disable-ai --verbose

echo
echo "✅ Demo completed successfully!"
echo "📁 Check the ./results directory for generated reports"
echo
echo "💡 To run with real tools in Kali Linux:"
echo "   unset OPENMANUS_DEMO_MODE"
echo "   python main.py --target example.com --mode comprehensive"