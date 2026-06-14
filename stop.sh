#!/bin/bash

if pkill -f "python3 src/server.py" 2>/dev/null; then
    echo "SIFT Sentinel stopped."
else
    echo "SIFT Sentinel is not running."
fi
