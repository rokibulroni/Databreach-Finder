"""Backward-compatible launcher.

The implementation now lives in the ``professor_osint`` package. This thin shim
keeps ``python professor_osint.py ...`` (and the Docker / install-script entry
points) working. When this file is executed as a script, ``import
professor_osint`` resolves to the package directory rather than this module.
"""
from professor_osint.cli import main

if __name__ == "__main__":
    main()
