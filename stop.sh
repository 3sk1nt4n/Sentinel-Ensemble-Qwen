#!/bin/bash

if pkill -f "python3 src/server.py" 2>/dev/null; then
    echo "Sentinel Qwen Ensemble stopped."
else
    echo "Sentinel Qwen Ensemble is not running."
fi
