import typing


class RoleValidatorInterface:
    def validate_roles(self, user_roles: typing.Sequence[str], mandatory_roles: typing.Sequence[str]) -> bool:
        pass
