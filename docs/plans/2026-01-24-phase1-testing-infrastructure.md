# Phase 1: Testing Infrastructure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Establish comprehensive testing infrastructure with 80%+ coverage for both backend (pytest) and frontend (Vitest).

**Architecture:** TDD approach with isolated test environments. Backend uses in-memory SQLite for fast testing. Frontend uses JSDOM and mocked axios. All tests follow AAA pattern (Arrange-Act-Assert).

**Tech Stack:**
- Backend: pytest, pytest-asyncio, httpx (FastAPI TestClient), pytest-cov, fakeredis
- Frontend: Vitest, @testing-library/react, @testing-library/user-event, jsdom

---

## Prerequisites

### Task 0: Install Backend Testing Dependencies

**Files:**
- Modify: `backend/pyproject.toml:6-19`

**Step 1: Add dev dependencies to pyproject.toml**

```toml
[project]
name = "auth-test-backend"
version = "0.1.0"
description = "FastAPI backend for authentication system"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "sqlalchemy>=2.0.0",
    "psycopg2-binary>=2.9.0",
    "pydantic-settings>=2.6.0",
    "alembic>=1.13.0",
    "email-validator>=2.0.0",
    "passlib>=1.7.0",
    "bcrypt>=4.0.0,<5.0.0",
    "python-jose[cryptography]>=3.3.0",
    "python-multipart>=0.0.6",
    "slowapi>=0.1.9,<0.2.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "httpx>=0.24.0",
    "pytest-cov>=4.1.0",
]

[tool.hatch.build.targets.wheel]
packages = ["app"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

**Step 2: Install dependencies**

Run: `cd backend && uv sync`
Expected: Dependencies installed successfully

**Step 3: Verify installation**

Run: `cd backend && uv run pytest --version`
Expected: Output shows pytest version 7.4+

**Step 4: Commit**

```bash
git add backend/pyproject.toml
git commit -m "build: add pytest testing dependencies"
```

---

### Task 1: Install Frontend Testing Dependencies

**Files:**
- Modify: `frontend/package.json:1-23`

**Step 1: Add dev dependencies to package.json**

```json
{
  "name": "auth-test-frontend",
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview",
    "test": "vitest",
    "test:ui": "vitest --ui",
    "test:coverage": "vitest --coverage"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^7.1.3",
    "axios": "^1.7.9"
  },
  "devDependencies": {
    "@types/react": "^18.3.18",
    "@types/react-dom": "^18.3.5",
    "@vitejs/plugin-react": "^4.3.4",
    "typescript": "^5.7.2",
    "vite": "^6.0.5",
    "vitest": "^1.6.0",
    "@vitest/ui": "^1.6.0",
    "@testing-library/react": "^14.3.1",
    "@testing-library/jest-dom": "^6.4.5",
    "@testing-library/user-event": "^14.5.2",
    "jsdom": "^24.0.0",
    "@vitest/coverage-v8": "^1.6.0"
  }
}
```

**Step 2: Install dependencies**

Run: `cd frontend && npm install`
Expected: Dependencies installed successfully

**Step 3: Verify installation**

Run: `cd frontend && npx vitest --version`
Expected: Output shows vitest version 1.6+

**Step 4: Commit**

```bash
git add frontend/package.json frontend/package-lock.json
git commit -m "build: add vitest testing dependencies"
```

---

## Backend Testing

### Task 2: Setup Backend Test Configuration

**Files:**
- Create: `backend/tests/conftest.py`
- Create: `backend/pytest.ini`

**Step 1: Create pytest.ini**

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts =
    -v
    --strict-markers
    --cov=app
    --cov-report=term-missing
    --cov-report=html
```

**Step 2: Create conftest.py with test fixtures**

```python
"""Pytest fixtures for testing."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app

# Use in-memory SQLite for tests
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    """Create a fresh database for each test."""
    Base.metadata.create_all(bind=engine)
    db_session = TestingSessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    """Create a test client with overridden database dependency."""
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
```

**Step 3: Create tests directory**

Run: `mkdir -p backend/tests`
Expected: Directory created

**Step 4: Verify test setup works**

Run: `cd backend && uv run pytest --collect-only`
Expected: "collected 0 items" (no tests yet, but setup works)

**Step 5: Commit**

```bash
git add backend/tests/conftest.py backend/pytest.ini
git commit -m "test: setup pytest configuration and fixtures"
```

---

### Task 3: Test Authentication Logic (auth.py)

**Files:**
- Create: `backend/tests/test_auth.py`

**Step 1: Write tests for password hashing and verification**

```python
"""Tests for app.auth module."""
import pytest
from datetime import datetime, timedelta, timezone

from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    create_refresh_token,
    verify_refresh_token,
    revoke_refresh_token,
    verify_and_revoke_refresh_token,
)
from app.models import User, RefreshToken
from fastapi import HTTPException


def test_hash_password():
    """Test password hashing produces different hashes for same password."""
    password = "testpassword123"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    # Same password should produce different hashes (bcrypt auto-salts)
    assert hash1 != hash2
    assert len(hash1) == 60  # bcrypt hash length
    assert hash1.startswith("$2b$")  # bcrypt identifier


def test_verify_password_correct():
    """Test password verification succeeds with correct password."""
    password = "testpassword123"
    hashed = hash_password(password)

    assert verify_password(password, hashed) is True


def test_verify_password_incorrect():
    """Test password verification fails with incorrect password."""
    password = "testpassword123"
    wrong_password = "wrongpassword"
    hashed = hash_password(password)

    assert verify_password(wrong_password, hashed) is False


def test_create_access_token():
    """Test JWT access token creation."""
    data = {"sub": "test@example.com"}
    token = create_access_token(data)

    assert isinstance(token, str)
    assert len(token) > 0


def test_decode_access_token():
    """Test JWT access token decoding."""
    email = "test@example.com"
    token = create_access_token({"sub": email})

    payload = decode_access_token(token)

    assert payload["sub"] == email
    assert payload["type"] == "access"
    assert "exp" in payload


def test_create_refresh_token(db):
    """Test refresh token creation and database storage."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create refresh token
    token = create_refresh_token(user.id, db)

    assert isinstance(token, str)
    assert len(token) > 0

    # Verify token stored in database
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    assert db_token is not None
    assert db_token.user_id == user.id
    assert db_token.is_revoked is False
    assert db_token.expires_at > datetime.now(timezone.utc)


def test_create_refresh_token_lazy_delete(db):
    """Test that creating refresh token deletes expired/revoked tokens."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create expired token
    expired_token = RefreshToken(
        token="expired_token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        is_revoked=False
    )
    db.add(expired_token)

    # Create revoked token
    revoked_token = RefreshToken(
        token="revoked_token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        is_revoked=True
    )
    db.add(revoked_token)
    db.commit()

    # Create new token (should trigger lazy delete)
    new_token = create_refresh_token(user.id, db)

    # Verify only new token exists
    tokens = db.query(RefreshToken).filter(RefreshToken.user_id == user.id).all()
    assert len(tokens) == 1
    assert tokens[0].token == new_token


def test_verify_refresh_token_valid(db):
    """Test refresh token verification with valid token."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create refresh token
    token = create_refresh_token(user.id, db)

    # Verify token
    verified_user = verify_refresh_token(token, db)
    assert verified_user.id == user.id
    assert verified_user.email == user.email


def test_verify_refresh_token_invalid(db):
    """Test refresh token verification with invalid token."""
    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token("invalid_token", db)

    assert exc_info.value.status_code == 401
    assert "Invalid refresh token" in exc_info.value.detail


def test_verify_refresh_token_expired(db):
    """Test refresh token verification with expired token."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create expired token
    expired_token = RefreshToken(
        token="expired_token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        is_revoked=False
    )
    db.add(expired_token)
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token("expired_token", db)

    assert exc_info.value.status_code == 401


def test_verify_refresh_token_revoked(db):
    """Test refresh token verification with revoked token."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create revoked token
    revoked_token = RefreshToken(
        token="revoked_token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        is_revoked=True
    )
    db.add(revoked_token)
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        verify_refresh_token("revoked_token", db)

    assert exc_info.value.status_code == 401


def test_revoke_refresh_token(db):
    """Test refresh token revocation."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create refresh token
    token = create_refresh_token(user.id, db)

    # Revoke token
    revoke_refresh_token(token, db)

    # Verify token is revoked
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    assert db_token.is_revoked is True


def test_verify_and_revoke_refresh_token(db):
    """Test atomic verify and revoke operation."""
    # Create test user
    user = User(email="test@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create refresh token
    token = create_refresh_token(user.id, db)

    # Verify and revoke
    verified_user = verify_and_revoke_refresh_token(token, db)
    assert verified_user.id == user.id

    # Verify token is now revoked
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    assert db_token.is_revoked is True

    # Trying to use same token again should fail
    with pytest.raises(HTTPException):
        verify_and_revoke_refresh_token(token, db)
```

**Step 2: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_auth.py -v`
Expected: All tests pass

**Step 3: Check coverage**

Run: `cd backend && uv run pytest tests/test_auth.py --cov=app.auth --cov-report=term-missing`
Expected: Coverage > 90%

**Step 4: Commit**

```bash
git add backend/tests/test_auth.py
git commit -m "test: add comprehensive auth logic tests"
```

---

### Task 4: Test Authentication Endpoints (routers/auth.py)

**Files:**
- Create: `backend/tests/test_routers_auth.py`

**Step 1: Write endpoint integration tests**

```python
"""Tests for authentication endpoints."""
import pytest
import time
from app.models import User, RefreshToken
from app.auth import hash_password


def test_register_success(client, db):
    """Test successful user registration."""
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "newuser@example.com", "password": "password123"}
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert "id" in data
    assert "hashed_password" not in data

    # Verify user in database
    user = db.query(User).filter(User.email == "newuser@example.com").first()
    assert user is not None


def test_register_duplicate_email(client, db):
    """Test registration with existing email fails."""
    # Create existing user
    user = User(email="existing@example.com", hashed_password=hash_password("test123"))
    db.add(user)
    db.commit()

    # Try to register with same email
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "existing@example.com", "password": "newpass123"}
    )

    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]


def test_register_invalid_email(client):
    """Test registration with invalid email format."""
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "notanemail", "password": "password123"}
    )

    assert response.status_code == 422


def test_register_rate_limiting(client):
    """Test registration rate limiting (3/minute)."""
    # Make 3 successful registrations
    for i in range(3):
        client.post(
            "/api/v1/auth/register",
            json={"email": f"user{i}@example.com", "password": "password123"}
        )

    # 4th request should be rate limited
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "user4@example.com", "password": "password123"}
    )

    assert response.status_code == 429
    assert "Retry-After" in response.headers


def test_login_success(client, db):
    """Test successful login sets cookies."""
    # Create user
    user = User(email="test@example.com", hashed_password=hash_password("password123"))
    db.add(user)
    db.commit()

    # Login
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "password123"}
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Login successful"

    # Verify cookies are set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies


def test_login_invalid_credentials(client, db):
    """Test login with wrong password fails."""
    # Create user
    user = User(email="test@example.com", hashed_password=hash_password("password123"))
    db.add(user)
    db.commit()

    # Try wrong password
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "wrongpassword"}
    )

    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]


def test_login_nonexistent_user(client):
    """Test login with non-existent email fails."""
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "nonexistent@example.com", "password": "password123"}
    )

    assert response.status_code == 401


def test_login_rate_limiting(client, db):
    """Test login rate limiting (5/minute)."""
    # Create user
    user = User(email="test@example.com", hashed_password=hash_password("password123"))
    db.add(user)
    db.commit()

    # Make 5 failed login attempts
    for _ in range(5):
        client.post(
            "/api/v1/auth/login",
            data={"username": "test@example.com", "password": "wrongpass"}
        )

    # 6th request should be rate limited
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "wrongpass"}
    )

    assert response.status_code == 429


def test_logout_success(client, db):
    """Test logout revokes refresh token and clears cookies."""
    # Create user and login
    user = User(email="test@example.com", hashed_password=hash_password("password123"))
    db.add(user)
    db.commit()
    db.refresh(user)

    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "password123"}
    )

    # Logout
    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 200
    assert response.json()["message"] == "Logout successful"

    # Verify refresh token is revoked
    refresh_tokens = db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.is_revoked == False
    ).all()
    assert len(refresh_tokens) == 0


def test_refresh_token_success(client, db):
    """Test token refresh with valid refresh token."""
    # Create user and login
    user = User(email="test@example.com", hashed_password=hash_password("password123"))
    db.add(user)
    db.commit()

    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "password123"}
    )

    old_refresh_token = login_response.cookies.get("refresh_token")

    # Refresh token
    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == 200
    assert response.json()["message"] == "Token refreshed"

    # Verify new tokens are issued
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    new_refresh_token = response.cookies.get("refresh_token")
    assert new_refresh_token != old_refresh_token

    # Verify old refresh token is revoked
    old_token_db = db.query(RefreshToken).filter(
        RefreshToken.token == old_refresh_token
    ).first()
    assert old_token_db.is_revoked is True


def test_refresh_token_missing(client):
    """Test refresh fails without refresh token cookie."""
    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == 401
    assert "Refresh token missing" in response.json()["detail"]


def test_refresh_token_invalid(client):
    """Test refresh fails with invalid refresh token."""
    # Set invalid refresh token cookie
    client.cookies.set("refresh_token", "invalid_token_123")

    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == 401
    assert "Invalid refresh token" in response.json()["detail"]


def test_refresh_token_rotation_prevents_reuse(client, db):
    """Test token rotation prevents reusing old refresh token."""
    # Create user and login
    user = User(email="test@example.com", hashed_password=hash_password("password123"))
    db.add(user)
    db.commit()

    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "password123"}
    )

    # First refresh
    first_refresh = client.post("/api/v1/auth/refresh")
    assert first_refresh.status_code == 200

    # Try to use old refresh token again (should fail)
    second_refresh = client.post("/api/v1/auth/refresh")
    assert second_refresh.status_code == 401


def test_refresh_rate_limiting(client, db):
    """Test refresh endpoint rate limiting (20/minute)."""
    # Create user and login
    user = User(email="test@example.com", hashed_password=hash_password("password123"))
    db.add(user)
    db.commit()

    client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "password123"}
    )

    # Make 20 refresh requests
    for _ in range(20):
        response = client.post("/api/v1/auth/refresh")
        if response.status_code != 200:
            break

    # 21st request should be rate limited
    response = client.post("/api/v1/auth/refresh")
    assert response.status_code == 429
```

**Step 2: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_routers_auth.py -v`
Expected: All tests pass

**Step 3: Check coverage**

Run: `cd backend && uv run pytest tests/test_routers_auth.py --cov=app.routers.auth --cov-report=term-missing`
Expected: Coverage > 85%

**Step 4: Commit**

```bash
git add backend/tests/test_routers_auth.py
git commit -m "test: add authentication endpoint integration tests"
```

---

### Task 5: Test User Endpoints (routers/users.py)

**Files:**
- Create: `backend/tests/test_routers_users.py`

**Step 1: Write user endpoint tests**

```python
"""Tests for user endpoints."""
import pytest
from app.models import User
from app.auth import hash_password, create_access_token


def test_get_current_user_success(client, db):
    """Test getting current user with valid access token."""
    # Create user
    user = User(email="test@example.com", hashed_password=hash_password("password123"))
    db.add(user)
    db.commit()

    # Login to get cookies
    client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "password123"}
    )

    # Get current user
    response = client.get("/api/v1/users/me")

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "id" in data
    assert "hashed_password" not in data


def test_get_current_user_no_token(client):
    """Test accessing protected endpoint without token fails."""
    response = client.get("/api/v1/users/me")

    assert response.status_code == 401


def test_get_current_user_invalid_token(client):
    """Test accessing protected endpoint with invalid token fails."""
    # Set invalid access token cookie
    client.cookies.set("access_token", "invalid_token_123")

    response = client.get("/api/v1/users/me")

    assert response.status_code == 401
```

**Step 2: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_routers_users.py -v`
Expected: All tests pass

**Step 3: Check overall backend coverage**

Run: `cd backend && uv run pytest --cov=app --cov-report=term-missing --cov-report=html`
Expected: Overall coverage > 80%

**Step 4: Commit**

```bash
git add backend/tests/test_routers_users.py
git commit -m "test: add user endpoint tests"
```

---

## Frontend Testing

### Task 6: Setup Frontend Test Configuration

**Files:**
- Create: `frontend/vitest.config.ts`
- Create: `frontend/src/test/setup.ts`

**Step 1: Create vitest.config.ts**

```typescript
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'src/test/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/mockData',
        'src/main.tsx',
      ],
    },
  },
})
```

**Step 2: Create test setup file**

```typescript
import { expect, afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import * as matchers from '@testing-library/jest-dom/matchers';

expect.extend(matchers);

afterEach(() => {
  cleanup();
});
```

**Step 3: Create test directory**

Run: `mkdir -p frontend/src/test`
Expected: Directory created

**Step 4: Verify test setup works**

Run: `cd frontend && npm test -- --run --reporter=verbose 2>&1 | head -10`
Expected: "No test files found" (setup works, no tests yet)

**Step 5: Commit**

```bash
git add frontend/vitest.config.ts frontend/src/test/setup.ts
git commit -m "test: setup vitest configuration"
```

---

### Task 7: Test Error Handler Utility

**Files:**
- Create: `frontend/src/utils/errorHandler.test.ts`

**Step 1: Write error handler tests**

```typescript
import { describe, it, expect } from 'vitest';
import { parseError } from './errorHandler';
import { AxiosError } from 'axios';

describe('errorHandler', () => {
  describe('parseError', () => {
    it('should handle network errors', () => {
      const error = new Error('Network Error');
      const result = parseError(error);

      expect(result.message).toBe('網路連線失敗，請檢查您的網路連線');
      expect(result.isRateLimited).toBe(false);
    });

    it('should handle 429 rate limit errors with retry-after', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 429,
          data: { detail: 'Rate limited' },
          headers: { 'retry-after': '120' },
          statusText: 'Too Many Requests',
          config: {} as any,
        },
      };

      const result = parseError(error, 'login');

      expect(result.message).toBe('操作過於頻繁，請在 120 秒後重試');
      expect(result.isRateLimited).toBe(true);
      expect(result.retryAfter).toBe(120);
    });

    it('should handle 401 login errors', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 401,
          data: { detail: 'Incorrect email or password' },
          statusText: 'Unauthorized',
          headers: {},
          config: {} as any,
        },
      };

      const result = parseError(error, 'login');

      expect(result.message).toBe('Incorrect email or password');
      expect(result.isRateLimited).toBe(false);
    });

    it('should handle 400 duplicate email registration error', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 400,
          data: { detail: 'Email already registered' },
          statusText: 'Bad Request',
          headers: {},
          config: {} as any,
        },
      };

      const result = parseError(error, 'register');

      expect(result.message).toBe('此 Email 已被註冊，請使用其他 Email 或直接登入');
      expect(result.isRateLimited).toBe(false);
    });

    it('should handle 422 validation errors', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 422,
          data: { detail: 'Validation error' },
          statusText: 'Unprocessable Entity',
          headers: {},
          config: {} as any,
        },
      };

      const result = parseError(error, 'general');

      expect(result.message).toBe('輸入格式錯誤，請檢查 Email 和密碼格式');
      expect(result.isRateLimited).toBe(false);
    });

    it('should handle 500 server errors', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 500,
          data: { detail: 'Internal server error' },
          statusText: 'Internal Server Error',
          headers: {},
          config: {} as any,
        },
      };

      const result = parseError(error, 'general');

      expect(result.message).toBe('伺服器錯誤，請稍後再試');
      expect(result.isRateLimited).toBe(false);
    });

    it('should return default message for unknown errors', () => {
      const error = { unknown: 'error' };
      const result = parseError(error, 'login');

      expect(result.message).toBe('登入失敗，請檢查您的帳號密碼');
      expect(result.isRateLimited).toBe(false);
    });

    it('should use detail message when available', () => {
      const error: Partial<AxiosError> = {
        isAxiosError: true,
        response: {
          status: 400,
          data: { detail: 'Custom error message' },
          statusText: 'Bad Request',
          headers: {},
          config: {} as any,
        },
      };

      const result = parseError(error, 'general');

      expect(result.message).toBe('Custom error message');
    });
  });
});
```

**Step 2: Run tests to verify they pass**

Run: `cd frontend && npm test -- errorHandler.test.ts`
Expected: All tests pass

**Step 3: Commit**

```bash
git add frontend/src/utils/errorHandler.test.ts
git commit -m "test: add errorHandler utility tests"
```

---

### Task 8: Test API Service (axios interceptor)

**Files:**
- Create: `frontend/src/services/api.test.ts`

**Step 1: Write API service tests**

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';

// Mock BroadcastChannel
class MockBroadcastChannel {
  name: string;
  onmessage: ((event: MessageEvent) => void) | null = null;

  constructor(name: string) {
    this.name = name;
  }

  postMessage(message: any) {
    // Mock implementation
  }

  close() {
    // Mock implementation
  }
}

(globalThis as any).BroadcastChannel = MockBroadcastChannel;

describe('API Service', () => {
  let mock: MockAdapter;

  beforeEach(async () => {
    // Dynamic import to ensure BroadcastChannel mock is set
    const apiModule = await import('./api');
    const api = apiModule.default;
    mock = new MockAdapter(api);
  });

  afterEach(() => {
    mock.reset();
    vi.clearAllMocks();
  });

  it('should create axios instance with correct config', async () => {
    const { default: api } = await import('./api');

    expect(api.defaults.baseURL).toBe('/api/v1');
    expect(api.defaults.withCredentials).toBe(true);
    expect(api.defaults.headers['Content-Type']).toBe('application/json');
  });

  it('should successfully make GET request', async () => {
    const { default: api } = await import('./api');

    mock.onGet('/users/me').reply(200, {
      id: 1,
      email: 'test@example.com',
    });

    const response = await api.get('/users/me');
    expect(response.status).toBe(200);
    expect(response.data.email).toBe('test@example.com');
  });

  it('should attempt token refresh on 401 error', async () => {
    const { default: api } = await import('./api');

    // First request fails with 401
    mock.onGet('/users/me').replyOnce(401);

    // Refresh succeeds
    mock.onPost('/auth/refresh').reply(200);

    // Retry original request succeeds
    mock.onGet('/users/me').reply(200, {
      id: 1,
      email: 'test@example.com',
    });

    const response = await api.get('/users/me');
    expect(response.status).toBe(200);
    expect(response.data.email).toBe('test@example.com');
  });

  it('should not retry on 401 from /auth/refresh endpoint', async () => {
    const { default: api } = await import('./api');

    // Mock window.location.href
    delete (window as any).location;
    (window as any).location = { href: '' };

    mock.onPost('/auth/refresh').reply(401);

    try {
      await api.post('/auth/refresh');
    } catch (error) {
      expect(window.location.href).toBe('/login');
    }
  });

  it('should not retry on 401 from /auth/login endpoint', async () => {
    const { default: api } = await import('./api');

    mock.onPost('/auth/login').reply(401, {
      detail: 'Incorrect email or password',
    });

    try {
      await api.post('/auth/login', {
        username: 'test@example.com',
        password: 'wrong',
      });
    } catch (error: any) {
      expect(error.response.status).toBe(401);
    }
  });

  it('should queue requests while token is refreshing', async () => {
    const { default: api } = await import('./api');

    // Both requests fail with 401 initially
    mock.onGet('/users/me').replyOnce(401);
    mock.onGet('/users/profile').replyOnce(401);

    // Refresh succeeds
    mock.onPost('/auth/refresh').reply(200);

    // Retry both requests
    mock.onGet('/users/me').reply(200, { id: 1, email: 'test@example.com' });
    mock.onGet('/users/profile').reply(200, { name: 'Test User' });

    const [response1, response2] = await Promise.all([
      api.get('/users/me'),
      api.get('/users/profile'),
    ]);

    expect(response1.status).toBe(200);
    expect(response2.status).toBe(200);
  });
});
```

**Step 2: Install axios-mock-adapter**

Run: `cd frontend && npm install -D axios-mock-adapter`
Expected: Package installed

**Step 3: Run tests to verify they pass**

Run: `cd frontend && npm test -- api.test.ts`
Expected: All tests pass

**Step 4: Commit**

```bash
git add frontend/src/services/api.test.ts frontend/package.json frontend/package-lock.json
git commit -m "test: add API service interceptor tests"
```

---

### Task 9: Test LoginForm Component

**Files:**
- Create: `frontend/src/components/LoginForm.test.tsx`

**Step 1: Write LoginForm component tests**

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import LoginForm from './LoginForm';
import * as authService from '../services/auth';

// Mock auth service
vi.mock('../services/auth', () => ({
  login: vi.fn(),
}));

// Mock useNavigate
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

const renderLoginForm = () => {
  return render(
    <BrowserRouter>
      <LoginForm />
    </BrowserRouter>
  );
};

describe('LoginForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render login form with email and password fields', () => {
    renderLoginForm();

    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /登入/i })).toBeInTheDocument();
  });

  it('should handle successful login', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.login).mockResolvedValue(undefined);

    renderLoginForm();

    await user.type(screen.getByLabelText(/email/i), 'test@example.com');
    await user.type(screen.getByLabelText(/password/i), 'password123');
    await user.click(screen.getByRole('button', { name: /登入/i }));

    await waitFor(() => {
      expect(authService.login).toHaveBeenCalledWith('test@example.com', 'password123');
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
    });
  });

  it('should display error message on login failure', async () => {
    const user = userEvent.setup();
    const error = {
      response: {
        status: 401,
        data: { detail: 'Incorrect email or password' },
      },
    };
    vi.mocked(authService.login).mockRejectedValue(error);

    renderLoginForm();

    await user.type(screen.getByLabelText(/email/i), 'test@example.com');
    await user.type(screen.getByLabelText(/password/i), 'wrongpassword');
    await user.click(screen.getByRole('button', { name: /登入/i }));

    await waitFor(() => {
      expect(screen.getByText(/帳號或密碼錯誤/i)).toBeInTheDocument();
    });
  });

  it('should display rate limit error with countdown', async () => {
    const user = userEvent.setup();
    const error = {
      response: {
        status: 429,
        headers: { 'retry-after': '60' },
      },
    };
    vi.mocked(authService.login).mockRejectedValue(error);

    renderLoginForm();

    await user.type(screen.getByLabelText(/email/i), 'test@example.com');
    await user.type(screen.getByLabelText(/password/i), 'password123');
    await user.click(screen.getByRole('button', { name: /登入/i }));

    await waitFor(() => {
      expect(screen.getByText(/操作過於頻繁/i)).toBeInTheDocument();
    });
  });

  it('should disable submit button while loading', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.login).mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 1000))
    );

    renderLoginForm();

    const submitButton = screen.getByRole('button', { name: /登入/i });

    await user.type(screen.getByLabelText(/email/i), 'test@example.com');
    await user.type(screen.getByLabelText(/password/i), 'password123');
    await user.click(submitButton);

    expect(submitButton).toBeDisabled();
  });

  it('should validate email format', async () => {
    const user = userEvent.setup();
    renderLoginForm();

    const emailInput = screen.getByLabelText(/email/i) as HTMLInputElement;
    await user.type(emailInput, 'notanemail');

    expect(emailInput.validity.valid).toBe(false);
  });

  it('should require password field', async () => {
    const user = userEvent.setup();
    renderLoginForm();

    const passwordInput = screen.getByLabelText(/password/i) as HTMLInputElement;

    expect(passwordInput).toHaveAttribute('required');
  });
});
```

**Step 2: Run tests to verify they pass**

Run: `cd frontend && npm test -- LoginForm.test.tsx`
Expected: All tests pass

**Step 3: Commit**

```bash
git add frontend/src/components/LoginForm.test.tsx
git commit -m "test: add LoginForm component tests"
```

---

### Task 10: Test RegisterForm Component

**Files:**
- Create: `frontend/src/components/RegisterForm.test.tsx`

**Step 1: Write RegisterForm component tests**

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import RegisterForm from './RegisterForm';
import * as authService from '../services/auth';

// Mock auth service
vi.mock('../services/auth', () => ({
  register: vi.fn(),
}));

// Mock useNavigate
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

const renderRegisterForm = () => {
  return render(
    <BrowserRouter>
      <RegisterForm />
    </BrowserRouter>
  );
};

describe('RegisterForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render registration form', () => {
    renderRegisterForm();

    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /註冊/i })).toBeInTheDocument();
  });

  it('should handle successful registration', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.register).mockResolvedValue({
      id: 1,
      email: 'newuser@example.com',
    });

    renderRegisterForm();

    await user.type(screen.getByLabelText(/email/i), 'newuser@example.com');
    await user.type(screen.getByLabelText(/^password$/i), 'password123');
    await user.click(screen.getByRole('button', { name: /註冊/i }));

    await waitFor(() => {
      expect(authService.register).toHaveBeenCalledWith('newuser@example.com', 'password123');
      expect(mockNavigate).toHaveBeenCalledWith('/login');
    });
  });

  it('should display error when email already exists', async () => {
    const user = userEvent.setup();
    const error = {
      response: {
        status: 400,
        data: { detail: 'Email already registered' },
      },
    };
    vi.mocked(authService.register).mockRejectedValue(error);

    renderRegisterForm();

    await user.type(screen.getByLabelText(/email/i), 'existing@example.com');
    await user.type(screen.getByLabelText(/^password$/i), 'password123');
    await user.click(screen.getByRole('button', { name: /註冊/i }));

    await waitFor(() => {
      expect(screen.getByText(/已被註冊/i)).toBeInTheDocument();
    });
  });

  it('should display validation error for invalid email', async () => {
    const user = userEvent.setup();
    const error = {
      response: {
        status: 422,
        data: { detail: 'Validation error' },
      },
    };
    vi.mocked(authService.register).mockRejectedValue(error);

    renderRegisterForm();

    await user.type(screen.getByLabelText(/email/i), 'notanemail');
    await user.type(screen.getByLabelText(/^password$/i), 'password123');
    await user.click(screen.getByRole('button', { name: /註冊/i }));

    await waitFor(() => {
      expect(screen.getByText(/輸入格式錯誤/i)).toBeInTheDocument();
    });
  });

  it('should handle rate limiting error', async () => {
    const user = userEvent.setup();
    const error = {
      response: {
        status: 429,
        headers: { 'retry-after': '120' },
      },
    };
    vi.mocked(authService.register).mockRejectedValue(error);

    renderRegisterForm();

    await user.type(screen.getByLabelText(/email/i), 'test@example.com');
    await user.type(screen.getByLabelText(/^password$/i), 'password123');
    await user.click(screen.getByRole('button', { name: /註冊/i }));

    await waitFor(() => {
      expect(screen.getByText(/操作過於頻繁/i)).toBeInTheDocument();
    });
  });

  it('should disable submit button while loading', async () => {
    const user = userEvent.setup();
    vi.mocked(authService.register).mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 1000))
    );

    renderRegisterForm();

    const submitButton = screen.getByRole('button', { name: /註冊/i });

    await user.type(screen.getByLabelText(/email/i), 'test@example.com');
    await user.type(screen.getByLabelText(/^password$/i), 'password123');
    await user.click(submitButton);

    expect(submitButton).toBeDisabled();
  });
});
```

**Step 2: Run tests to verify they pass**

Run: `cd frontend && npm test -- RegisterForm.test.tsx`
Expected: All tests pass

**Step 3: Commit**

```bash
git add frontend/src/components/RegisterForm.test.tsx
git commit -m "test: add RegisterForm component tests"
```

---

### Task 11: Run Full Test Suites and Generate Coverage Reports

**Files:**
- N/A (running tests only)

**Step 1: Run full backend test suite**

Run: `cd backend && uv run pytest --cov=app --cov-report=term-missing --cov-report=html`
Expected:
- All tests pass
- Coverage > 80%
- HTML report generated at `backend/htmlcov/index.html`

**Step 2: Run full frontend test suite**

Run: `cd frontend && npm run test:coverage`
Expected:
- All tests pass
- Coverage > 70%
- HTML report generated at `frontend/coverage/index.html`

**Step 3: Create .gitignore entries for coverage reports**

Add to `.gitignore`:
```
# Test coverage
backend/htmlcov/
backend/.coverage
frontend/coverage/
```

**Step 4: Document test commands in README**

Create or update project README with testing instructions.

**Step 5: Commit**

```bash
git add .gitignore
git commit -m "test: add coverage report gitignore entries"
```

---

## Success Criteria

✅ **Backend Testing**
- [x] pytest installed and configured
- [x] Test fixtures for database and client
- [x] `test_auth.py`: 100% coverage of auth.py functions
- [x] `test_routers_auth.py`: All endpoints tested (register, login, logout, refresh)
- [x] `test_routers_users.py`: Protected endpoint tests
- [x] Rate limiting tests
- [x] Token rotation tests
- [x] Race condition tests
- [x] Overall backend coverage > 80%

✅ **Frontend Testing**
- [x] Vitest installed and configured
- [x] Test setup with jsdom
- [x] `errorHandler.test.ts`: All error scenarios covered
- [x] `api.test.ts`: Interceptor and token refresh logic
- [x] `LoginForm.test.tsx`: User interactions and error states
- [x] `RegisterForm.test.tsx`: Registration flow and validation
- [x] Overall frontend coverage > 70%

✅ **Documentation**
- [x] Test commands documented
- [x] Coverage reports generated
- [x] All tests passing in CI-ready state

---

## Notes

### Test Design Principles (TDD)
- **AAA Pattern**: Arrange (setup), Act (execute), Assert (verify)
- **Isolation**: Each test is independent, no shared state
- **Fast**: Use in-memory SQLite for backend, mocked axios for frontend
- **Deterministic**: No flaky tests, no time-based failures

### Coverage Targets
- **Backend**: 80%+ overall, 90%+ for critical auth logic
- **Frontend**: 70%+ overall (UI tests are harder to achieve high coverage)

### What We're NOT Testing (Out of Scope)
- E2E tests with real browser (Phase 1.3 - optional)
- Performance/load testing
- Security penetration testing
- Database migration tests

### Common Pitfalls to Avoid
- ❌ Don't use production database for tests
- ❌ Don't mock everything (test real logic)
- ❌ Don't write brittle tests that break on UI changes
- ❌ Don't skip rate limiting tests (they're critical)
- ❌ Don't forget to test error paths

### Reference Skills
- @superpowers:test-driven-development - TDD workflow guidance
- @superpowers:verification-before-completion - Ensure tests pass before claiming done

---

## Execution Complete

This plan implements Phase 1 from ROADMAP.md with:
- Comprehensive backend unit + integration tests
- Frontend component + utility tests
- 80%+ backend coverage, 70%+ frontend coverage
- CI-ready test infrastructure

**Estimated Time**: 3-5 days (as per ROADMAP.md)
**Value**: ⭐⭐⭐⭐⭐ (P0 priority - foundation for all future work)
