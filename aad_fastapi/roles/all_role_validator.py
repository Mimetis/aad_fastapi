import typing

from aad_fastapi.roles.role_validator_interface import RoleValidatorInterface


class AllRoleValidator(RoleValidatorInterface):
    def validate_roles(
        self, user_roles: typing.Sequence[str], mandatory_roles: typing.Sequence[str]
    ) -> bool:
        return all(mandatory_role in user_roles for mandatory_role in mandatory_roles)
