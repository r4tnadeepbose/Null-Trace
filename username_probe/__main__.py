#! /usr/bin/env python3

"""
Username Probe: Find Handles Across Public Profiles

This module contains the main logic to search for usernames at social
networks.
"""

import sys


if __name__ == "__main__":
    # Check if the user is using the correct version of Python
    python_version = sys.version.split()[0]

    if sys.version_info < (3, 9):
        print(f"Username Probe requires Python 3.9+\nYou are using Python {python_version}, which is not supported.")
        sys.exit(1)

    from username_probe import probe
    probe.main()
