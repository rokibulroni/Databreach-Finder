"""Standalone / PyInstaller entry point for Professor OSINT.

Uses a distinct filename (not ``professor_osint.py``) so the frozen build's
entry module never collides with the ``professor_osint`` package.
"""
from professor_osint.cli import main

if __name__ == "__main__":
    main()
