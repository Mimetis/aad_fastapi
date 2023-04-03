import typing

from aad_fastapi.roles.all_role_validator import AllRoleValidator
from aad_fastapi.roles.any_role_validator import AnyRoleValidator
from aad_fastapi.roles.role_requirement import RoleRequirement


class RoleValidator:
    """Role validator class"""

    _validators = {
        RoleRequirement.ALL: AllRoleValidator,
        RoleRequirement.ANY: AnyRoleValidator,
    }

    def __init__(
        self, mandatory_roles: typing.List[str], role_requirement: RoleRequirement
    ):
        self.mandatory_roles = mandatory_roles
        self.role_requirement = role_requirement
        self.validator_class = self._validators.get(role_requirement)
        if self.validator_class is None:
            raise ValueError(f"Invalid role requirement: {role_requirement}")

    def validate_roles(self, user_roles: typing.List[str]) -> bool:
        """validate the user roles against the mandatory roles"""
        validator = self.validator_class()
        return validator.validate_roles(user_roles, self.mandatory_roles)
