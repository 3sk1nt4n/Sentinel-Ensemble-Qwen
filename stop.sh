#!/bin/bash

if pkill -f "python3 src/server.py" 2>/dev/null; then
    echo "Sentinel Ensemble stopped."
else
    echo "Sentinel Ensemble is not running."
fi
