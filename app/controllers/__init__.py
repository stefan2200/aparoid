"""
Small snip to make from controllers import * work
"""

import os
import glob

# Load all controllers from current directory
__all__ = [
    os.path.basename(f)[:-3] for f in glob.glob(
        f"{os.path.dirname(__file__)}/*.py"
    )
]
