"""
Pytest configuration and fixtures for DNS-Loki tests
"""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from controller.main import app
from controller.services.database_service import DatabaseService
from controller.services.auth_service import AuthService
from controller.models.auth import UserCreate


# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def test_db() -> AsyncGenerator[AsyncSession, None]:
    """Create test database session"""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    
    async with engine.begin() as conn:
        # Create tables
        await conn.run_sync(DatabaseService.metadata.create_all)
    
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()


@pytest.fixture
def test_client() -> TestClient:
    """Create test client"""
    return TestClient(app)


@pytest.fixture
async def test_user(test_db: AsyncSession):
    """Create test user"""
    auth_service = AuthService()
    user_data = UserCreate(
        username="testuser",
        email="test@example.com",
        password="testpass123",
        full_name="Test User"
    )
    user = await auth_service.create_user(user_data)
    return user


@pytest.fixture
async def test_admin(test_db: AsyncSession):
    """Create test admin user"""
    auth_service = AuthService()
    admin_data = UserCreate(
        username="admin",
        email="admin@example.com",
        password="adminpass123",
        full_name="Admin User",
        is_admin=True
    )
    admin = await auth_service.create_user(admin_data)
    return admin


@pytest.fixture
async def auth_headers(test_user):
    """Get authentication headers for test user"""
    auth_service = AuthService()
    token = await auth_service.create_access_token(
        data={"sub": test_user.username}
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def admin_headers(test_admin):
    """Get authentication headers for admin user"""
    auth_service = AuthService()
    token = await auth_service.create_access_token(
        data={"sub": test_admin.username}
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_node_data():
    """Sample node data for testing"""
    return {
        "ip": "192.168.1.100",
        "name": "test-node",
        "location": "US",
        "ssh_user": "root",
        "ssh_password": "password",
        "ssh_port": 22,
        "roles": ["dns", "proxy"]
    }


@pytest.fixture
def test_client_data():
    """Sample client data for testing"""
    return {
        "ip": "10.0.0.100",
        "name": "test-client",
        "type": "both",
        "active": True,
        "description": "Test client"
    }


@pytest.fixture
def test_config_data():
    """Sample configuration data for testing"""
    return {
        "dns": {
            "upstream_servers": ["8.8.8.8", "8.8.4.4"],
            "cache_size": 10000,
            "ttl": 300
        },
        "proxy": {
            "port": 443,
            "workers": 4,
            "timeout": 30
        },
        "flags": {
            "enforce_dns_clients": True,
            "enable_monitoring": True,
            "debug_mode": False
        }
    }
