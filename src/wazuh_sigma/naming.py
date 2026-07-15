"""Canonical names used by converted Sigma rules."""

import re


NAMING_VERSION = "sigma-group-name-v1"


def sigma_group_name(name: str) -> str:
    """Return a stable Wazuh group in the required ``sigma_{NAME}`` form."""
    slug = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    if slug.startswith("sigma_"):
        return slug
    return f"sigma_{slug or 'unnamed'}"
