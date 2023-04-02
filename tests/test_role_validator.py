import pytest

from aad_fastapi.roles.all_role_validator import AllRoleValidator
from aad_fastapi.roles.any_role_validator import AnyRoleValidator
from aad_fastapi.roles.role_requirement import RoleRequirement
from aad_fastapi.roles.role_validator import RoleValidator


@pytest.mark.parametrize(
    "roles, requirement, user_roles, expected",
    [
        (["admin", "editor"], RoleRequirement.ALL, ["admin", "editor"], True),
        (["admin", "editor"], RoleRequirement.ALL, ["admin"], False),
        (["admin", "editor"], RoleRequirement.ANY, ["admin"], True),
        (["admin", "editor"], RoleRequirement.ANY, ["guest"], False),
    ],
)
def test_role_validator(roles, requirement, user_roles, expected):
    validator = RoleValidator(roles, requirement)
    assert validator.validate_roles(user_roles) == expected


def test_role_validator_invalid_role_requirement():
    with pytest.raises(ValueError):
        RoleValidator([], "invalid")


@pytest.mark.parametrize(
    "mandatory_roles, user_roles, expected",
    [
        (["admin", "editor"], ["admin", "editor"], True),
        (["admin", "editor"], ["admin"], False),
    ],
)
def test_all_role_validator(mandatory_roles, user_roles, expected):
    validator = AllRoleValidator()
    assert validator.validate_roles(user_roles, mandatory_roles) == expected


@pytest.mark.parametrize(
    "mandatory_roles, user_roles, expected",
    [
        (["admin", "editor"], ["admin"], True),
        (["admin", "editor"], ["guest"], False),
    ],
)
def test_any_role_validator(mandatory_roles, user_roles, expected):
    validator = AnyRoleValidator()
    assert validator.validate_roles(user_roles, mandatory_roles) == expected
