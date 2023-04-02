import pytest

from aad_fastapi.roles.role_validator import RoleValidator
from aad_fastapi.roles.any_role_validator import AnyRoleValidator
from aad_fastapi.roles.all_role_validator import AllRoleValidator
from aad_fastapi.roles.role_requirement import RoleRequirement


def test_role_validator_all():
    validator = RoleValidator(['admin', 'editor'], RoleRequirement.ALL)
    user_roles = ['admin', 'editor']
    assert validator.validate_roles(user_roles)


def test_role_validator_all_fail():
    validator = RoleValidator(['admin', 'editor'], RoleRequirement.ALL)
    user_roles = ['admin']
    assert not validator.validate_roles(user_roles)


def test_role_validator_any():
    validator = RoleValidator(['admin', 'editor'], RoleRequirement.ANY)
    user_roles = ['admin']
    assert validator.validate_roles(user_roles)


def test_role_validator_any_fail():
    validator = RoleValidator(['admin', 'editor'], RoleRequirement.ANY)
    user_roles = ['guest']
    assert not validator.validate_roles(user_roles)


def test_role_validator_invalid_role_requirement():
    with pytest.raises(ValueError):
        RoleValidator([], 'invalid')


def test_all_role_validator():
    validator = AllRoleValidator()
    mandatory_roles = ['admin', 'editor']
    user_roles = ['admin', 'editor']
    assert validator.validate_roles(user_roles, mandatory_roles)


def test_all_role_validator_fail():
    validator = AllRoleValidator()
    mandatory_roles = ['admin', 'editor']
    user_roles = ['admin']
    assert not validator.validate_roles(user_roles, mandatory_roles)


def test_any_role_validator():
    validator = AnyRoleValidator()
    mandatory_roles = ['admin', 'editor']
    user_roles = ['admin']
    assert validator.validate_roles(user_roles, mandatory_roles)


def test_any_role_validator_fail():
    validator = AnyRoleValidator()
    mandatory_roles = ['admin', 'editor']
    user_roles = ['guest']
    assert not validator.validate_roles(user_roles, mandatory_roles)