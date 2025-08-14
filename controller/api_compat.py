#!/usr/bin/env python3
"""
Compatibility wrapper for the old api.py
This ensures backward compatibility while transitioning to the new structure
"""

import sys
import os
from pathlib import Path

# Add the parent directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the main app
from controller.main import app

# Export app for uvicorn
__all__ = ['app']

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
