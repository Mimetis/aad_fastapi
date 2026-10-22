import typing
from abc import ABC, abstractmethod


class RoleValidatorInterface(ABC):
    @abstractmethod
    def validate_roles(
        self, user_roles: typing.Sequence[str], mandatory_roles: typing.Sequence[str]
    ) -> bool:
        """validate the user roles against the mandatory roles"""
