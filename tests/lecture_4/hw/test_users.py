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

# создаем клиент для тестирования
app = create_app()


# фикстура для установки состояния приложения (инициализация user_service)
@pytest.fixture
def client():
    # Инициализация user_service с пользователями
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

    # Присваиваем user_service в состояние приложения
    app.state.user_service = user_service
    with TestClient(app) as client:
        yield client


# Параметризация теста для проверки различных случаев регистрации пользователя
@pytest.mark.parametrize(
    "user_data, expected_status_code",
    [
        # Успешная регистрация пользователя
        ({"username": "user1", "name": "User One", "birthdate": "1990-01-01T00:00:00", "password": "StrongPassword123"},
         200),

        # Ошибка из-за короткого пароля
        ({"username": "user2", "name": "User Two", "birthdate": "1990-01-01T00:00:00", "password": "short"}, 400),

        # Ошибка из-за отсутствия цифры в пароле
        (
        {"username": "user3", "name": "User Three", "birthdate": "1990-01-01T00:00:00", "password": "NoDigitsPassword"},
        400),
        # Ошибка из-за использования уже существующего имени пользователя
        ({"username": "admin", "name": "Admin", "birthdate": "1970-01-01T00:00:00", "password": "StrongPassword123"},
         400)
    ]
)
def test_register_user_parametrized(client, user_data, expected_status_code):
    # Делаем POST запрос на эндпоинт регистрации с параметризованными данными
    response = client.post("/user-register", json=user_data)

    # Проверяем, что код ответа соответствует ожидаемому
    assert response.status_code == expected_status_code

@pytest.mark.parametrize(
    "params, expected_status_code, expected_response_detail",
    [
        # Успешное получение пользователя по username
        ({"username": "test_user"}, 200, None),

        # Ошибка при передаче и id, и username одновременно
        ({"id": 2, "username": "test_user"}, 400, "both id and username are provided"),

        # Ошибка при отсутствии id и username
        ({}, 400, "neither id nor username are provided"),

        # Ошибка при запросе несуществующего пользователя
        ({"id": 999}, 404, "Not Found")
    ]
)

def test_get_user(client, params, expected_status_code, expected_response_detail):
    # Добавляем данные для авторизации
    auth_headers = {
        "Authorization": "Basic YWRtaW46c3VwZXJTZWNyZXRBZG1pblBhc3N3b3JkMTIz"  # admin:superSecretAdminPassword123
    }

    # Регистрируем пользователя "test_user" для тестирования успешного получения
    user_data = {
        "username": "test_user",
        "name": "Test User",
        "birthdate": "1990-01-01T00:00:00",
        "password": "StrongPassword123"
    }
    client.post("/user-register", json=user_data, headers=auth_headers)

    # Делаем запрос на получение пользователя
    response = client.post("/user-get", params=params, headers=auth_headers)

    # Проверяем, что статус-код соответствует ожидаемому
    assert response.status_code == expected_status_code

    # Если ожидается ошибка, проверяем содержание ответа
    if expected_response_detail:
        assert response.json()["detail"] == expected_response_detail
    # Если успешный запрос, проверяем корректность полей ответа
    else:
        user_response = response.json()
        assert user_response["username"] == "test_user"
        assert user_response["name"] == "Test User"
        assert user_response["birthdate"] == "1990-01-01T00:00:00"

@pytest.mark.parametrize(
    "user_data, promote_id, auth_headers, expected_status_code, expected_detail",
    [
        # Успешная промоция пользователя
        (
            {"username": "test_user", "name": "Test User", "birthdate": "1990-01-01T00:00:00", "password": "StrongPassword123"},
            2,  # id пользователя, которого будем промотировать
            {"Authorization": "Basic YWRtaW46c3VwZXJTZWNyZXRBZG1pblBhc3N3b3JkMTIz"},  # admin:superSecretAdminPassword123
            200, None
        ),

        # Ошибка промоции несуществующего пользователя
        (
            {"username": "test_user", "name": "Test User", "birthdate": "1990-01-01T00:00:00", "password": "StrongPassword123"},
            999,  # Не существующий id
            {"Authorization": "Basic YWRtaW46c3VwZXJTZWNyZXRBZG1pblBhc3N3b3JkMTIz"},  # admin:superSecretAdminPassword123
            404, "user not found"
        ),

        # Ошибка промоции без прав администратора
        (
            {"username": "test_user", "name": "Test User", "birthdate": "1990-01-01T00:00:00", "password": "StrongPassword123"},
            2,  # id пользователя, которого будем промотировать
            {"Authorization": "Basic dGVzdF91c2VyOlN0cm9uZ1Bhc3N3b3JkMTIz"},  # test_user:StrongPassword123
            403, "Forbidden"
        )
    ]
)
def test_promote_user_parametrized(client, user_data, promote_id, auth_headers, expected_status_code, expected_detail):
    # Регистрируем пользователя перед промоцией
    register_response = client.post("/user-register", json=user_data, headers=auth_headers)
    assert register_response.status_code == 200

    # Делаем запрос на промоцию пользователя
    response = client.post("/user-promote", params={"id": promote_id}, headers=auth_headers)

    # Проверяем, что статус-код ответа соответствует ожидаемому
    assert response.status_code == expected_status_code

    # Если ожидается ошибка, проверяем содержимое ошибки
    if expected_detail:
        assert response.json()["detail"] == expected_detail
    # Если успешная промоция, проверяем, что роль пользователя теперь ADMIN
    elif response.status_code == 200:
        promoted_user_response = client.post("/user-get", params={"id": promote_id}, headers=auth_headers)
        assert promoted_user_response.status_code == 200
        assert promoted_user_response.json()["role"] == UserRole.ADMIN



# Тест для проверки выбрасываемого исключения UNAUTHORIZED
def test_requires_author_unauthorized():
    # Создаем user_service и добавляем тестового пользователя
    user_service = UserService(password_validators=[])

    # Регистрация пользователя "valid_user"
    user_service.register(UserInfo(
        username="valid_user",
        name="Valid User",
        birthdate="1990-01-01T00:00:00",
        password=SecretStr("correct_password"),
        role=UserRole.USER
    ))

    # Подаем неправильные учетные данные
    credentials = HTTPBasicCredentials(username="valid_user", password="wrong_password")

    # Проверяем, что при неправильном пароле выбрасывается HTTPException с кодом 401
    with pytest.raises(HTTPException) as exc_info:
        requires_author(credentials, user_service)

    assert exc_info.value.status_code == HTTPStatus.UNAUTHORIZED

def test_get_by_username_returns_none():
    # Создаем экземпляр UserService
    user_service = UserService(password_validators=[])

    # Проверяем, что при запросе несуществующего пользователя возвращается None
    result = user_service.get_by_username("non_existing_user")
    assert result is None


def test_grant_admin_user_not_found():
    # Создаем экземпляр UserService
    user_service = UserService(password_validators=[])

    # Проверяем, что при попытке сделать несуществующего пользователя администратором
    # выбрасывается исключение ValueError с сообщением "user not found"
    with pytest.raises(ValueError) as exc_info:
        user_service.grant_admin(999)  # 999 - несуществующий user_id

    # Проверяем, что сообщение исключения соответствует ожидаемому
    assert str(exc_info.value) == "user not found"