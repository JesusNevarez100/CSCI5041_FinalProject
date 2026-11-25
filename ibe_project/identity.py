"""Deliberately restricted ASCII identity policy shared by both workflows."""

import re

PREFIX = "csci4041:email-ibe:v1:"


def canonical_email(email: str) -> str:
    """Preserve local-part case, dots and tags; lowercase the domain.

    This is a prototype input policy, not a complete RFC email parser or
    evidence of mailbox ownership. Quoted and internationalized addresses
    are outside its scope.
    """
    email = email.strip()
    if not email.isascii() or email.count("@") != 1:
        raise ValueError("Expected a simple ASCII email address")
    local, domain = email.split("@")
    if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+", local):
        raise ValueError("Unsupported email local part")
    if len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
        raise ValueError("Invalid email local part")
    labels = domain.split(".")
    if len(labels) < 2 or len(email) > 254:
        raise ValueError("Expected a domain with at least two labels")
    if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
           for label in labels):
        raise ValueError("Invalid email domain")
    return f"{local}@{domain.lower()}"


def ibe_identity(email: str) -> str:
    """Pass this same string to Charm encrypt() and extract()."""
    return PREFIX + canonical_email(email)
