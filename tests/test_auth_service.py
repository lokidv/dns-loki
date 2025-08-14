"""
Tests for Authentication Service
"""

import pytest
from datetime import datetime, timedelta
from controller.services.auth_service import AuthService
from controller.models.auth import UserCreate, UserUpdate


@pytest.mark.asyncio
async def test_create_user():
    """Test user creation"""
    auth_service = AuthService()
    
    user_data = UserCreate(
        username="newuser",
        email="new@example.com",
        password="password123",
        full_name="New User"
    )
    
    user = await auth_service.create_user(user_data)
    
    assert user.username == "newuser"
    assert user.email == "new@example.com"
    assert user.full_name == "New User"
    assert user.is_active is True
    assert user.is_admin is False


@pytest.mark.asyncio
async def test_authenticate_user():
    """Test user authentication"""
    auth_service = AuthService()
    
    # Create user
    user_data = UserCreate(
        username="authuser",
        email="auth@example.com",
        password="password123"
    )
    await auth_service.create_user(user_data)
    
    # Test authentication
    authenticated = await auth_service.authenticate_user("authuser", "password123")
    assert authenticated is not None
    assert authenticated.username == "authuser"
    
    # Test wrong password
    wrong_auth = await auth_service.authenticate_user("authuser", "wrongpass")
    assert wrong_auth is None


@pytest.mark.asyncio
async def test_create_access_token():
    """Test JWT token creation"""
    auth_service = AuthService()
    
    token = await auth_service.create_access_token(
        data={"sub": "testuser"},
        expires_delta=timedelta(minutes=30)
    )
    
    assert token is not None
    assert isinstance(token, str)
    assert len(token) > 0


@pytest.mark.asyncio
async def test_verify_token():
    """Test JWT token verification"""
    auth_service = AuthService()
    
    # Create token
    token = await auth_service.create_access_token(
        data={"sub": "testuser"},
        expires_delta=timedelta(minutes=30)
    )
    
    # Verify token
    payload = await auth_service.verify_token(token)
    assert payload is not None
    assert payload.get("sub") == "testuser"


@pytest.mark.asyncio
async def test_change_password():
    """Test password change"""
    auth_service = AuthService()
    
    # Create user
    user_data = UserCreate(
        username="passuser",
        email="pass@example.com",
        password="oldpass123"
    )
    await auth_service.create_user(user_data)
    
    # Change password
    result = await auth_service.change_password("passuser", "newpass123")
    assert result is True
    
    # Test authentication with new password
    authenticated = await auth_service.authenticate_user("passuser", "newpass123")
    assert authenticated is not None
    
    # Old password should not work
    old_auth = await auth_service.authenticate_user("passuser", "oldpass123")
    assert old_auth is None


@pytest.mark.asyncio
async def test_api_key_management():
    """Test API key creation and validation"""
    auth_service = AuthService()
    
    # Create user
    user_data = UserCreate(
        username="apiuser",
        email="api@example.com",
        password="password123"
    )
    user = await auth_service.create_user(user_data)
    
    # Generate API key
    api_key = await auth_service.generate_api_key(
        user.username,
        "test-key",
        expires_in_days=30
    )
    
    assert api_key is not None
    assert "key" in api_key
    assert "id" in api_key
    
    # Validate API key
    validated_user = await auth_service.validate_api_key(api_key["key"])
    assert validated_user is not None
    assert validated_user.username == "apiuser"
    
    # List API keys
    keys = await auth_service.list_api_keys(user.username)
    assert len(keys) > 0
    
    # Revoke API key
    result = await auth_service.revoke_api_key(api_key["id"], user.username)
    assert result is True
    
    # Validation should fail after revocation
    invalid_user = await auth_service.validate_api_key(api_key["key"])
    assert invalid_user is None
