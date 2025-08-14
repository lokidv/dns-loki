#!/usr/bin/env python3
"""
Runner script for DNS-Loki Controller
This script properly sets up the Python path and runs the FastAPI application
"""

import sys
import os
from pathlib import Path

# Add the parent directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

if __name__ == "__main__":
    import uvicorn
    from controller.core.config import settings
    
    uvicorn.run(
        "controller.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
