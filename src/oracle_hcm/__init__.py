"""Oracle-HCM AI Auto-Coding Engine.

Importing the package loads the .env file into the process environment. The
file is optional, its contents are never printed, and values already present
in the environment win over the file.
"""

from __future__ import annotations

from oracle_hcm.config.env import load_env

__all__ = ["__version__", "load_env"]

__version__ = "0.1.0"

load_env()
