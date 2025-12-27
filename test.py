import pytest
import pytest_asyncio
import uuid
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
from main import app


async def mock_rate_limiter_call(self, request, response):
    return None


@pytest.fixture(autouse=True)
def disable_rate_limiter():
    with patch(
            "fastapi_limiter.depends.RateLimiter.__call__",
            new=mock_rate_limiter_call
    ):
        yield


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(
            transport=transport,
            base_url="http://test"
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def registered_user(client):
    username = f"user_{uuid.uuid4().hex[:6]}"
    password = "StrongPassword123!"
    email = f"{username}@example.com"

    response = await client.post(
        "/users/register",
        json={
            "username": username,
            "password": password,
            "email": email
        }
    )
    assert response.status_code == 200

    return {
        "username": username,
        "password": password
    }


@pytest.mark.asyncio
async def test_register_user(client):
    username = f"user_{uuid.uuid4().hex[:6]}"

    response = await client.post(
        "/users/register",
        json={
            "username": username,
            "password": "StrongPassword12334!",
            "email": f"{username}@example.com"
        }
    )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_login_user(client, registered_user):
    response = await client.post(
        "/users/login",
        data={
            "username": registered_user["username"],
            "password": registered_user["password"]
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    assert response.status_code == 200
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_register_login_refresh():
    # Патчим Utils (отключаем хэш и верификацию) и RateLimiter
    with patch("main.Utils.password_hash", side_effect=lambda x: x), \
            patch("main.Utils.verify_password", side_effect=lambda x, y: x == y), \
            patch("fastapi_limiter.depends.RateLimiter.__call__", new=mock_rate_limiter_call):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # -----------------------------
            # 1️⃣ Регистрация пользователя
            # -----------------------------
            username = f"user_{uuid.uuid4().hex[:6]}"
            email = f"{username}@example.com"
            password = "StrongPassword123!"

            register_data = {
                "username": username,
                "password": password,
                "email": email
            }
            response = await ac.post("/users/register", json=register_data)
            assert response.status_code == 200, f"Register failed: {response.text}"
            user_id = response.json()["id"]

            # -----------------------------
            # 2️⃣ Логин
            # -----------------------------
            login_data = {
                "username": username,
                "password": password
            }
            response = await ac.post(
                "/users/login",
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            assert response.status_code == 200, f"Login failed: {response.text}"
            tokens = response.json()
            access_token = tokens["access_token"]
            refresh_token = tokens["refresh_token"]

            # -----------------------------
            # 3️⃣ Проверка защищенного эндпоинта
            # -----------------------------
            response = await ac.get("/projects", headers={"Authorization": f"Bearer {access_token}"})
            assert response.status_code == 200, f"Protected endpoint failed: {response.text}"

            # -----------------------------
            # 4️⃣ Использование refresh токена
            # -----------------------------
            response = await ac.post(
                "/users/refresh",
                json={"refresh_token": refresh_token}
            )
            assert response.status_code == 200, f"Refresh failed: {response.text}"
            new_tokens = response.json()
            assert "access_token" in new_tokens
            assert "refresh_token" in new_tokens

        # Очистка переопределений
        app.dependency_overrides = {}


@pytest.mark.asyncio
async def test_register_login_refresh_logout():
    # Патчим Utils (отключаем хэш и верификацию) и RateLimiter
    with patch("main.Utils.password_hash", side_effect=lambda x: x), \
            patch("main.Utils.verify_password", side_effect=lambda x, y: x == y), \
            patch("fastapi_limiter.depends.RateLimiter.__call__", new=mock_rate_limiter_call):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # -----------------------------
            # 1️⃣ Регистрация пользователя
            # -----------------------------
            username = f"user_{uuid.uuid4().hex[:6]}"
            email = f"{username}@example.com"
            password = "StrongPassword123!"

            register_data = {
                "username": username,
                "password": password,
                "email": email
            }
            response = await ac.post("/users/register", json=register_data)
            assert response.status_code == 200, f"Register failed: {response.text}"
            user_id = response.json()["id"]

            # -----------------------------
            # 2️⃣ Логин
            # -----------------------------
            login_data = {
                "username": username,
                "password": password
            }
            response = await ac.post(
                "/users/login",
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            assert response.status_code == 200, f"Login failed: {response.text}"
            tokens = response.json()
            access_token = tokens["access_token"]
            refresh_token = tokens["refresh_token"]

            # -----------------------------
            # 3️⃣ Проверка защищенного эндпоинта
            # -----------------------------
            response = await ac.get("/projects", headers={"Authorization": f"Bearer {access_token}"})
            assert response.status_code == 200, f"Protected endpoint failed: {response.text}"

            # -----------------------------
            # 4️⃣ Использование refresh токена
            # -----------------------------
            response = await ac.post(
                "/users/refresh",
                json={"refresh_token": refresh_token}
            )
            assert response.status_code == 200, f"Refresh failed: {response.text}"
            new_tokens = response.json()
            assert "access_token" in new_tokens
            assert "refresh_token" in new_tokens

            # -----------------------------
            # 5️⃣ Logout
            # -----------------------------
            response = await ac.post(
                "/users/logout",
                json={"refresh_token": new_tokens["refresh_token"]}
            )
            assert response.status_code == 200, f"Logout failed: {response.text}"
            assert response.json()["message"] == "Successfully logged out"

        # Очистка переопределений
        app.dependency_overrides = {}
