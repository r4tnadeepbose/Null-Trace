""" Username Probe Engine Module

This module contains the main logic to search for usernames at social
networks.

Vendored inside Null-Trace: no packaging metadata and no tomli dependency, so
the upstream version is pinned here and kept in sync with resources/data.json.
"""

ENGINE_VERSION = "0.16.2"


def get_version() -> str:
    """Fetch the version number of the vendored engine."""
    return ENGINE_VERSION

# This variable is only used to check for ImportErrors induced by users running as script rather than as module or package
import_error_test_var = None

__shortname__   = "Username Probe"
__longname__    = "Username Probe: Find Handles Across Public Profiles"
__version__     = get_version()
