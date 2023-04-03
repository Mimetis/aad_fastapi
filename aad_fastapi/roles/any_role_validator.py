import typing

from aad_fastapi.roles.role_validator_interface import RoleValidatorInterface


class AnyRoleValidator(RoleValidatorInterface):
    """Validate that at least one mandatory role is present in the user roles"""

    def validate_roles(
        self, user_roles: typing.Sequence[str], mandatory_roles: typing.Sequence[str]
    ) -> bool:
        return any(mandatory_role in user_roles for mandatory_role in mandatory_roles)
