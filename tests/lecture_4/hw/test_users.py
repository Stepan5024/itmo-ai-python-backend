from http import HTTPStatus

import pytest
from fastapi.security import HTTPBasicCredentials
from fastapi.testclient import TestClient
from pydantic import SecretStr
from fastapi import HTTPException

from lecture_4.demo_service.api.main import create_app
from lecture_4.demo_service.api.utils import requires_author
from lecture_4.demo_service.core.users import UserService, UserInfo, UserRole
from datetime import datetime


app = create_app()


@pytest.fixture
def client():
    user_service = UserService(
        password_validators=[
            lambda pwd: len(pwd) > 8,
            lambda pwd: any(char.isdigit() for char in pwd)
        ]
    )

    user_service.register(UserInfo(
        username="admin",
        name="admin",
        birthdate=datetime(1970, 1, 1),
        password="superSecretAdminPassword123",
        role=UserRole.ADMIN
    ))

    user_service.register(UserInfo(
        username="test_user",
        name="Test User",
        birthdate=datetime(1990, 1, 1),
        password="StrongPassword123",
        role=UserRole.USER
    ))

    app.state.user_service = user_service
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize(
    "user_data, expected_status_code",
    [
        ({"username": "user1", "name": "User One", "birthdate": "1990-01-01T00:00:00", "password": "StrongPassword123"},
         200),
        ({"username": "user2", "name": "User Two", "birthdate": "1990-01-01T00:00:00", "password": "short"}, 400),
        ({"username": "user3", "name": "User Three", "birthdate": "1990-01-01T00:00:00", "password": "NoDigitsPassword"},
        400),
        ({"username": "admin", "name": "Admin", "birthdate": "1970-01-01T00:00:00", "password": "StrongPassword123"},
         400)
    ]
)
def test_register_user_parametrized(client, user_data, expected_status_code):
    response = client.post("/user-register", json=user_data)

    assert response.status_code == expected_status_code

@pytest.mark.parametrize(
    "params, expected_status_code, expected_response_detail",
    [
        ({"username": "test_user"}, 200, None),

        ({"id": 2, "username": "test_user"}, 400, "both id and username are provided"),
        ({}, 400, "neither id nor username are provided"),

        ({"id": 999}, 404, "Not Found")
    ]
)

def test_get_user(client, params, expected_status_code, expected_response_detail):
    auth_headers = {
        "Authorization": "Basic YWRtaW46c3VwZXJTZWNyZXRBZG1pblBhc3N3b3JkMTIz"
    }

    user_data = {
        "username": "test_user",
        "name": "Test User",
        "birthdate": "1990-01-01T00:00:00",
        "password": "StrongPassword123"
    }
    client.post("/user-register", json=user_data, headers=auth_headers)
    response = client.post("/user-get", params=params, headers=auth_headers)

    assert response.status_code == expected_status_code

    if expected_response_detail:
        assert response.json()["detail"] == expected_response_detail
    else:
        user_response = response.json()
        assert user_response["username"] == "test_user"
        assert user_response["name"] == "Test User"
        assert user_response["birthdate"] == "1990-01-01T00:00:00"

@pytest.mark.parametrize(
    "user_data, promote_id, auth_headers, expected_status_code, expected_detail",
    [
        (
            {"username": "test_user", "name": "Test User", "birthdate": "1990-01-01T00:00:00", "password": "StrongPassword123"},
            2,
            {"Authorization": "Basic YWRtaW46c3VwZXJTZWNyZXRBZG1pblBhc3N3b3JkMTIz"},
            200, None
        ),

        (
            {"username": "test_user", "name": "Test User", "birthdate": "1990-01-01T00:00:00", "password": "StrongPassword123"},
            999,
            {"Authorization": "Basic YWRtaW46c3VwZXJTZWNyZXRBZG1pblBhc3N3b3JkMTIz"},
            404, "user not found"
        ),


        (
            {"username": "test_user", "name": "Test User", "birthdate": "1990-01-01T00:00:00", "password": "StrongPassword123"},
            2,
            {"Authorization": "Basic dGVzdF91c2VyOlN0cm9uZ1Bhc3N3b3JkMTIz"},
            403, "Forbidden"
        )
    ]
)
def test_promote_user_parametrized(client, user_data, promote_id, auth_headers, expected_status_code, expected_detail):
    register_response = client.post("/user-register", json=user_data, headers=auth_headers)
    assert register_response.status_code == 200

    response = client.post("/user-promote", params={"id": promote_id}, headers=auth_headers)

    assert response.status_code == expected_status_code

    if expected_detail:
        assert response.json()["detail"] == expected_detail
    elif response.status_code == 200:
        promoted_user_response = client.post("/user-get", params={"id": promote_id}, headers=auth_headers)
        assert promoted_user_response.status_code == 200
        assert promoted_user_response.json()["role"] == UserRole.ADMIN

def test_requires_author_unauthorized():
    user_service = UserService(password_validators=[])

    user_service.register(UserInfo(
        username="valid_user",
        name="Valid User",
        birthdate="1990-01-01T00:00:00",
        password=SecretStr("correct_password"),
        role=UserRole.USER
    ))

    credentials = HTTPBasicCredentials(username="valid_user", password="wrong_password")

    with pytest.raises(HTTPException) as exc_info:
        requires_author(credentials, user_service)

    assert exc_info.value.status_code == HTTPStatus.UNAUTHORIZED

def test_get_by_username_returns_none():
    user_service = UserService(password_validators=[])

    result = user_service.get_by_username("non_existing_user")
    assert result is None


def test_grant_admin_user_not_found():
    user_service = UserService(password_validators=[])

    with pytest.raises(ValueError) as exc_info:
        user_service.grant_admin(999)  # 999 - несуществующий user_id
    assert str(exc_info.value) == "user not found"