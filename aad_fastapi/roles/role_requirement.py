from enum import Enum


class RoleRequirement(Enum):
    """Role requirement enum for authorization."""

    ALL = "all"
    ANY = "any"
