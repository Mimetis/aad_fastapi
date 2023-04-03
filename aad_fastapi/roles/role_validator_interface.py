import typing


class RoleValidatorInterface:
    def validate_roles(
        self, user_roles: typing.Sequence[str], mandatory_roles: typing.Sequence[str]
    ) -> bool:
        """validate the user roles against the mandatory roles"""
