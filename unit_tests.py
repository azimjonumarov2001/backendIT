import pytest
from main import Utils, create_access_token, create_refresh_token
from jose import jwt
from main import SECRET_KEY, ALGORITHM


# -----------------------
# 1️⃣ Тестирование Utils.password_hash и Utils.verify_password
# -----------------------
def test_password_hash_and_verify():
    password = "StrongPassword123!"
    hashed = Utils.password_hash(password)

    # Проверяем, что verify_password возвращает True для правильного пароля
    assert Utils.verify_password(password, hashed) is True

    # Проверяем, что verify_password возвращает False для неправильного пароля
    assert Utils.verify_password("WrongPassword", hashed) is False


# -----------------------
# 2️⃣ Тестирование create_access_token
# -----------------------
def test_create_access_token():
    user_id = 1
    role = "user"
    token = create_access_token(user_id, role)

    assert isinstance(token, str)

    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == str(user_id)
    assert payload["role"] == role
    assert payload["type"] == "access"


# -----------------------
# 3️⃣ Тестирование create_refresh_token
# -----------------------
def test_create_refresh_token():
    user_id = 42
    role = "admin"
    token = create_refresh_token(user_id, role)

    assert isinstance(token, str)

    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == str(user_id)
    assert payload["role"] == role
    assert payload["type"] == "refresh"
