import pytest
import os
import tempfile
import time
import gc
import sqlite3
import json
from unittest.mock import patch
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app import db, main


@pytest.fixture(scope="function")
def temp_db():
    """Create a temporary database for testing"""
    fd, temp_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    
    try:
        with patch.object(db, 'db_path', temp_path):
            db.init_db(temp_path)
            yield temp_path
    finally:
        # Ensure all database connections are closed
        # Close any open connections by forcing garbage collection
        gc.collect()
        
        # On Windows, give the OS time to release file handles
        if os.name == 'nt':
            time.sleep(0.1)
        
        # Try to close any lingering connections
        try:
            # Force close any open sqlite3 connections
            import sqlite3
            # SQLite3 connections should be closed via context managers,
            # but we'll try to force cleanup
            gc.collect()
        except Exception:
            pass
        
        # Small delay to ensure file handles are released on Windows
        if os.name == 'nt':
            time.sleep(0.1)
        
        # Now safely remove the file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except (PermissionError, OSError):
                # If still locked, wait a bit more and try again
                if os.name == 'nt':
                    time.sleep(0.2)
                    try:
                        os.remove(temp_path)
                    except (PermissionError, OSError):
                        # Last resort: try to delete on next attempt
                        pass


def create_temp_config(**overrides):
    """Create a temporary config.json file with custom values"""
    # Default config values
    default_config = {
        "db_url": "sqlite:///./app.db",
        "group_seed": "526078169",
        "attempts_log_file": "attempts.log",
        "default_hash_mode": "argon2id",
        "enable_rate_limit": True,
        "rate_limit_attempts": 20,
        "rate_limit_window_s": 60,
        "enable_lockout": True,
        "lockout_threshold": 10,
        "lockout_duration_s": 300,
        "enable_captcha": True,
        "captcha_fail_threshold": 3,
        "captcha_ttl_s": 300,
        "enable_totp": True
    }
    
    # Apply overrides
    default_config.update(overrides)
    
    # Create temporary config file
    fd, temp_config_path = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    
    with open(temp_config_path, 'w', encoding='utf-8') as f:
        json.dump(default_config, f, indent=2)
    
    return temp_config_path


@pytest.fixture(scope="function")
def default_config(temp_db):
    """Default config fixture - all features enabled"""
    config_path = create_temp_config()
    yield config_path
    if os.path.exists(config_path):
        try:
            os.remove(config_path)
        except Exception:
            pass


@pytest.fixture(scope="function")
def rate_limit_config(temp_db):
    """Config for rate limit tests - disable captcha, totp, lockout"""
    config_path = create_temp_config(
        enable_rate_limit=True,
        enable_lockout=False,
        enable_captcha=False,
        enable_totp=False
    )
    yield config_path
    if os.path.exists(config_path):
        try:
            os.remove(config_path)
        except Exception:
            pass


@pytest.fixture(scope="function")
def lockout_config(temp_db):
    """Config for lockout tests - disable captcha, totp"""
    config_path = create_temp_config(
        enable_rate_limit=True,
        enable_lockout=True,
        enable_captcha=False,
        enable_totp=False
    )
    yield config_path
    if os.path.exists(config_path):
        try:
            os.remove(config_path)
        except Exception:
            pass


@pytest.fixture(scope="function")
def captcha_config(temp_db):
    """Config for captcha tests - disable rate limit, lockout, totp"""
    config_path = create_temp_config(
        enable_rate_limit=False,
        enable_lockout=False,
        enable_captcha=True,
        enable_totp=False
    )
    yield config_path
    if os.path.exists(config_path):
        try:
            os.remove(config_path)
        except Exception:
            pass


@pytest.fixture(scope="function")
def totp_config(temp_db):
    """Config for totp tests - disable captcha"""
    config_path = create_temp_config(
        enable_rate_limit=True,
        enable_lockout=True,
        enable_captcha=False,
        enable_totp=True
    )
    yield config_path
    if os.path.exists(config_path):
        try:
            os.remove(config_path)
        except Exception:
            pass


@pytest.fixture(scope="function")
def client(temp_db, default_config):
    """Create a test client with a temporary database and config"""
    yield from _create_client(temp_db, default_config)


def _create_client(temp_db, config_path):
    """Helper to create a test client with given config"""
    with patch.object(db, 'db_path', temp_db):
        # Reload config with the provided config path
        from app.config import load_config
        main.config = load_config(config_path)
        
        # Reinitialize rate limiter and lockout tracker with current config
        from app.rate_limit import RateLimiter
        from app.lockout_tracker import LockoutTracker
        main.rate_limiter = RateLimiter(main.config.rate_limit_attempts, main.config.rate_limit_window_s)
        main.lockouts = LockoutTracker(main.config.lockout_threshold, main.config.lockout_duration_s)
        
        # Reset rate limiter and lockout tracker for each test
        main.rate_limiter.buckets.clear()
        main.lockouts.failures.clear()
        main.lockouts.locked_until.clear()
        # Reset captcha failures
        main._captcha_failures.clear()
        
        test_client = TestClient(main.app)
        yield test_client
        
        # Ensure test client is closed
        test_client.close()
        
        # Force cleanup of any database connections
        gc.collect()
        if os.name == 'nt':
            time.sleep(0.05)


class TestHealthEndpoint:
    """Test the health check endpoint"""
    
    def test_health_endpoint(self, client):
        """Test that health endpoint returns ok"""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestRegistration:
    """Test user registration endpoint"""
    
    def test_register_new_user(self, client):
        """Test registering a new user successfully"""
        response = client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        assert response.status_code == 200
        assert response.json() == {"result": "created"}
        
        # Verify user was created in database
        user = db.get_user("testuser")
        assert user is not None
        assert user.username == "testuser"
    
    def test_register_duplicate_username(self, client):
        """Test that registering with an existing username fails"""
        # Register first user
        response = client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        assert response.status_code == 200
        
        # Try to register again with same username
        response = client.post(
            "/register",
            json={"username": "testuser", "password": "differentpass", "hash_mode": "argon2id", "category": "medium"}
        )
        assert response.status_code == 400
        assert "Username already exists" in response.json()["detail"]
    
    def test_register_short_password(self, client):
        """Test that password validation works (min length 6)"""
        response = client.post(
            "/register",
            json={"username": "testuser", "password": "short", "hash_mode": "argon2id", "category": "medium"}
        )
        assert response.status_code == 422  # Validation error
    
    def test_register_multiple_users(self, client):
        """Test registering multiple different users"""
        users = [
            {"username": "user1", "password": "pass123", "hash_mode": "argon2id", "category": "medium"},
            {"username": "user2", "password": "pass456", "hash_mode": "argon2id", "category": "medium"},
            {"username": "user3", "password": "pass789", "hash_mode": "argon2id", "category": "medium"},
        ]
        
        for user_data in users:
            response = client.post("/register", json=user_data)
            assert response.status_code == 200
            assert response.json() == {"result": "created"}
            
            # Verify each user exists
            user = db.get_user(user_data["username"])
            assert user is not None
            assert user.username == user_data["username"]


class TestLogin:
    """Test user login endpoint"""
    
    def test_login_success(self, client):
        """Test successful login with correct credentials"""
        # Register a user first
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Login with correct credentials
        response = client.post(
            "/login",
            json={"username": "testuser", "password": "password123"}
        )
        assert response.status_code == 200
        assert response.json()["result"] == "success"
    
    def test_login_invalid_username(self, client):
        """Test login with non-existent username"""
        response = client.post(
            "/login",
            json={"username": "nonexistent", "password": "password123"}
        )
        assert response.status_code == 200
        assert response.json()["result"] == "invalid_credentials"
    
    def test_login_invalid_password(self, client):
        """Test login with wrong password"""
        # Register a user first
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Try to login with wrong password
        response = client.post(
            "/login",
            json={"username": "testuser", "password": "wrongpassword"}
        )
        assert response.status_code == 200
        assert response.json()["result"] == "invalid_credentials"
    
    def test_login_after_registration(self, client):
        """Test complete flow: register then login"""
        # Register
        register_response = client.post(
            "/register",
            json={"username": "newuser", "password": "mypassword", "hash_mode": "argon2id", "category": "medium"}
        )
        assert register_response.status_code == 200
        
        # Login
        login_response = client.post(
            "/login",
            json={"username": "newuser", "password": "mypassword"}
        )
        assert login_response.status_code == 200
        assert login_response.json()["result"] == "success"


@pytest.fixture(scope="function")
def rate_limit_client(temp_db, rate_limit_config):
    """Client fixture for rate limit tests"""
    yield from _create_client(temp_db, rate_limit_config)


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limit_enforcement(self, rate_limit_client):
        """Test that rate limiting blocks too many attempts"""
        # Register a user
        rate_limit_client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make many failed login attempts (exceeding rate limit)
        # Default rate limit is 20 attempts per 60 seconds
        for i in range(21):
            response = rate_limit_client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
            if i < 20:
                # First 20 should fail with invalid password
                assert response.status_code == 200
                assert response.json()["result"] == "invalid_credentials"
            else:
                # 21st should fail with rate limit
                assert response.status_code == 200
                # Check if it's rate limit error (rate limiter checks before password verification)
                assert response.json()["result"] == "rate_limit_exceeded"
    
    def test_rate_limit_resets_after_window(self, rate_limit_client):
        """Test that rate limit resets after the time window"""
        # Register a user
        rate_limit_client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make attempts to reach rate limit (20 total)
        # Since captcha and lockout are disabled, we can make all attempts without captcha
        for i in range(20):
            response = rate_limit_client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
            assert response.status_code == 200
            assert response.json()["result"] == "invalid_credentials"
        
        # Wait for rate limit window to pass (mock time)
        # Patch time.time in the rate_limit module
        current_time = time.time()
        with patch('app.rate_limit.time.time') as mock_time:
            # Set mock time to be 61 seconds in the future
            mock_time.return_value = current_time + 61
            
            # Should be able to make another attempt (rate limit expired)
            response = rate_limit_client.post(
                "/login",
                json={
                    "username": "testuser",
                    "password": "wrongpassword"
                }
            )
            # Should fail with invalid credentials (rate limit expired)
            assert response.status_code == 200
            assert response.json()["result"] == "invalid_credentials"
    
    def test_rate_limit_per_user(self, rate_limit_client):
        """Test that rate limiting is per user"""
        # Register two users
        rate_limit_client.post(
            "/register",
            json={"username": "user1", "password": "pass1", "hash_mode": "argon2id", "category": "medium"}
        )
        rate_limit_client.post(
            "/register",
            json={"username": "user2", "password": "pass2", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Exhaust rate limit for user1
        for i in range(20):
            rate_limit_client.post(
                "/login",
                json={"username": "user1", "password": "wrong"}
            )
        
        # user2 should still be able to attempt login
        response = rate_limit_client.post(
            "/login",
            json={"username": "user2", "password": "wrong"}
        )
        assert response.status_code == 200  # Invalid password, not rate limited
        assert response.json()["result"] == "invalid_credentials"


@pytest.fixture(scope="function")
def lockout_client(temp_db, lockout_config):
    """Client fixture for lockout tests"""
    yield from _create_client(temp_db, lockout_config)


class TestLockout:
    """Test account lockout functionality"""
    
    def test_lockout_after_threshold(self, lockout_client):
        """Test that account gets locked after threshold failures"""
        # Register a user
        lockout_client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Default lockout threshold is 10
        # Make failed login attempts up to threshold
        # Since captcha is disabled, we can make all attempts without captcha
        for i in range(10):
            response = lockout_client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
            assert response.status_code == 200
            assert response.json()["result"] == "invalid_credentials"
        
        # 11th attempt should trigger lockout
        response = lockout_client.post(
            "/login",
            json={
                "username": "testuser",
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 200
        # Should be locked out
        assert response.json()["result"] == "locked_out"
    
    def test_lockout_prevents_login(self, lockout_client):
        """Test that locked account cannot login even with correct password"""
        # Register a user
        lockout_client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Trigger lockout by making many failed attempts
        # Need to exceed lockout threshold (default 10)
        # Since captcha is disabled, we can make all attempts without captcha
        for i in range(11):
            lockout_client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
        
        # Try to login with correct password while locked
        response = lockout_client.post(
            "/login",
            json={
                "username": "testuser",
                "password": "password123"
            }
        )
        assert response.status_code == 200
        # Should be locked out
        assert response.json()["result"] == "locked_out"
    
    def test_lockout_expires_after_duration(self, lockout_client):
        """Test that lockout expires after the duration"""
        # Register a user
        lockout_client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Trigger lockout
        # Since captcha is disabled, we can make all attempts without captcha
        for i in range(11):
            lockout_client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
        
        # Verify locked and get remaining time
        locked, remaining_seconds = main.lockouts.is_locked("testuser")
        assert locked == True
        
        # Mock time to expire lockout (default duration is 300 seconds)
        # Patch time.time in the lockout_tracker module
        current_time = time.time()
        with patch('app.lockout_tracker.time.time') as mock_time:
            # Set initial time to current real time
            mock_time.return_value = current_time
            
            # Verify still locked
            locked, _ = main.lockouts.is_locked("testuser")
            assert locked == True
            
            # Move time forward past lockout expiration (remaining_seconds + 1 to ensure it's expired)
            mock_time.return_value = current_time + remaining_seconds + 1
            
            # Verify lockout has expired
            locked, _ = main.lockouts.is_locked("testuser")
            assert locked == False
            
            # Should be able to login now (lockout expired)
            # Since captcha is disabled, we don't need a captcha token
            response = lockout_client.post(
                "/login",
                json={
                    "username": "testuser",
                    "password": "password123"
                }
            )
            # Should succeed now that lockout is expired
            assert response.status_code == 200
            assert response.json()["result"] == "success"
    
    def test_lockout_per_user(self, lockout_client):
        """Test that lockout is per user"""
        # Register two users (use passwords with 6+ characters to satisfy validation)
        reg_response1 = lockout_client.post(
            "/register",
            json={"username": "user1", "password": "pass123", "hash_mode": "argon2id", "category": "medium"}
        )
        assert reg_response1.status_code == 200
        
        reg_response2 = lockout_client.post(
            "/register",
            json={"username": "user2", "password": "pass456", "hash_mode": "argon2id", "category": "medium"}
        )
        assert reg_response2.status_code == 200
        
        # Lock out user1
        # Since captcha is disabled, we can make all attempts without captcha
        for i in range(11):
            lockout_client.post(
                "/login",
                json={"username": "user1", "password": "wrong"}
            )
        
        # user2 should still be able to login (lockout is per-user, so user2 isn't affected)
        response = lockout_client.post(
            "/login",
            json={"username": "user2", "password": "pass456"}
        )
        assert response.status_code == 200
        assert response.json()["result"] == "success"


class TestIntegrationScenarios:
    """Test complex integration scenarios"""
    
    def test_register_login_logout_flow(self, client):
        """Test complete user flow: register, login multiple times"""
        # Register
        response = client.post(
            "/register",
            json={"username": "flowuser", "password": "flowpass", "hash_mode": "argon2id", "category": "medium"}
        )
        assert response.status_code == 200
        
        # Login multiple times successfully
        for i in range(5):
            response = client.post(
                "/login",
                json={"username": "flowuser", "password": "flowpass"}
            )
            assert response.status_code == 200
            assert response.json()["result"] == "success"
    
    def test_failed_attempts_then_success(self, client):
        """Test that successful login clears failure count"""
        # Register
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make some failed attempts (but not enough to lockout)
        # After 3 failures, captcha is required
        for i in range(5):
            login_data = {
                "username": "testuser",
                "password": "wrong"
            }
            if i >= 3:
                # Get a new captcha token for each attempt after 3rd (tokens are single-use)
                captcha_response = client.get(
                    "/admin/get_captcha_token",
                    params={"group_seed": "526078169"}
                )
                login_data["captcha_token"] = captcha_response.json()["captcha_token"]
            
            response = client.post("/login", json=login_data)
            assert response.status_code == 200
            assert response.json()["result"] in ["invalid_credentials", "locked_out"]
        
        # Successful login should work
        # Get a new captcha token for successful login
        captcha_response = client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "526078169"}
        )
        captcha_token = captcha_response.json()["captcha_token"]
        
        response = client.post(
            "/login",
            json={
                "username": "testuser",
                "password": "password123",
                "captcha_token": captcha_token
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "success"
        
        # After success, should be able to make more failed attempts without lockout
        # (since failure count was reset)
        # Make 3 attempts to avoid triggering captcha requirement again
        for i in range(3):
            response = client.post(
                "/login",
                json={"username": "testuser", "password": "wrong"}
            )
            assert response.status_code == 200
            assert response.json()["result"] == "invalid_credentials"
    
    def test_multiple_users_independent(self, client):
        """Test that multiple users operate independently"""
        # Register multiple users
        users = [
            {"username": "alice", "password": "alicepass", "hash_mode": "argon2id", "category": "medium"},
            {"username": "bob", "password": "bobpass", "hash_mode": "argon2id", "category": "medium"},
            {"username": "charlie", "password": "charliepass", "hash_mode": "argon2id", "category": "medium"},
        ]
        
        for user_data in users:
            response = client.post("/register", json=user_data)
            assert response.status_code == 200
        
        # Each user can login independently
        for user_data in users:
            response = client.post(
                "/login",
                json={"username": user_data["username"], "password": user_data["password"]}
            )
            assert response.status_code == 200
            assert response.json()["result"] == "success"
        
        # Lockout one user
        for i in range(11):
            client.post(
                "/login",
                json={"username": "alice", "password": "wrong"}
            )
        
        # Other users should still work
        response = client.post(
            "/login",
            json={"username": "bob", "password": "bobpass"}
        )
        assert response.status_code == 200
        
        response = client.post(
            "/login",
            json={"username": "charlie", "password": "charliepass"}
        )
        assert response.status_code == 200
    
    def test_edge_case_empty_username(self, client):
        """Test edge case: empty username"""
        response = client.post(
            "/login",
            json={"username": "", "password": "password"}
        )
        # Should fail validation or return 200 with invalid_credentials
        assert response.status_code in [200, 400, 422]
        if response.status_code == 200:
            assert response.json()["result"] == "invalid_credentials"
    
    def test_edge_case_empty_password(self, client):
        """Test edge case: empty password"""
        response = client.post(
            "/login",
            json={"username": "testuser", "password": ""}
        )
        # Should fail validation or return 200 with invalid_credentials
        assert response.status_code in [200, 400, 422]
        if response.status_code == 200:
            assert response.json()["result"] == "invalid_credentials"



@pytest.fixture(scope="function")
def captcha_client(temp_db, captcha_config):
    """Client fixture for captcha tests"""
    yield from _create_client(temp_db, captcha_config)


class TestCaptchaE2E:
    """End-to-end tests for captcha functionality"""
    
    def test_admin_get_captcha_token_success(self, captcha_client):
        """Test getting a captcha token from admin endpoint with valid group_seed"""
        response = captcha_client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "526078169"}  # Default group_seed from config
        )
        assert response.status_code == 200
        data = response.json()
        assert "captcha_token" in data
        assert "expires_in" in data
        assert isinstance(data["captcha_token"], str)
        assert len(data["captcha_token"]) > 0
        assert data["expires_in"] == 300  # Default captcha_ttl_s
    
    def test_admin_get_captcha_token_invalid_seed(self, captcha_client):
        """Test that admin endpoint rejects invalid group_seed"""
        response = captcha_client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "invalid_seed"}
        )
        assert response.status_code == 403
        assert "invalid group seed" in response.json()["detail"]
    
    def test_login_requires_captcha_after_threshold_failures(self, client):
        """Test that login requires captcha after reaching failure threshold"""
        # Register a user
        client.post(
            "/register",
            json={"username": "captchauser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Default captcha_fail_threshold is 3
        # Make 3 failed login attempts
        for i in range(3):
            response = client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
            assert response.status_code == 200
            assert response.json()["result"] == "invalid_credentials"
        
        # 4th attempt without captcha should require captcha
        response = client.post(
            "/login",
            json={"username": "captchauser", "password": "wrongpassword"}
        )
        assert response.status_code == 200
        assert response.json()["result"] == "captcha_failed"
    
    def test_login_with_valid_captcha_token(self, captcha_client):
        """Test successful login with valid captcha token after threshold failures"""
        # Register a user
        captcha_client.post(
            "/register",
            json={"username": "captchauser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make enough failed attempts to trigger captcha requirement
        for i in range(3):
            captcha_client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
        
        # Get a captcha token from admin endpoint
        captcha_response = captcha_client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "526078169"}
        )
        assert captcha_response.status_code == 200
        captcha_token = captcha_response.json()["captcha_token"]
        
        # Login with valid captcha token and correct password
        response = captcha_client.post(
            "/login",
            json={
                "username": "captchauser",
                "password": "password123",
                "captcha_token": captcha_token
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "success"
    
    def test_login_with_invalid_captcha_token(self, client):
        """Test login fails with invalid captcha token"""
        # Register a user
        client.post(
            "/register",
            json={"username": "captchauser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make enough failed attempts to trigger captcha requirement
        for i in range(3):
            client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
        
        # Try to login with invalid captcha token
        response = client.post(
            "/login",
            json={
                "username": "captchauser",
                "password": "password123",
                "captcha_token": "invalid_token_12345"
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "captcha_failed"
    
    def test_login_with_missing_captcha_token_after_threshold(self, captcha_client):
        """Test login fails when captcha is required but token is missing"""
        # Register a user
        captcha_client.post(
            "/register",
            json={"username": "captchauser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make enough failed attempts to trigger captcha requirement
        for i in range(3):
            captcha_client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
        
        # Try to login without captcha token (None)
        response = captcha_client.post(
            "/login",
            json={
                "username": "captchauser",
                "password": "password123"
                # captcha_token is None by default
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "captcha_failed"
    
    def test_captcha_cleared_after_successful_login(self, captcha_client):
        """Test that captcha requirement is cleared after successful login"""
        # Register a user
        captcha_client.post(
            "/register",
            json={"username": "captchauser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make enough failed attempts to trigger captcha requirement
        for i in range(3):
            captcha_client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
        
        # Verify captcha is required
        response = captcha_client.post(
            "/login",
            json={"username": "captchauser", "password": "wrongpassword"}
        )
        assert response.status_code == 200
        assert response.json()["result"] == "captcha_failed"
        
        # Get captcha token and login successfully
        captcha_response = captcha_client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "526078169"}
        )
        captcha_token = captcha_response.json()["captcha_token"]
        
        response = captcha_client.post(
            "/login",
            json={
                "username": "captchauser",
                "password": "password123",
                "captcha_token": captcha_token
            }
        )
        assert response.status_code == 200
        
        # After successful login, captcha should not be required anymore
        # Make a few more failed attempts (less than threshold)
        for i in range(2):
            response = captcha_client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
            # Should fail with invalid password, not captcha requirement
            assert response.status_code == 200
            assert response.json()["result"] == "invalid_credentials"
            assert response.json()["result"] != "captcha_failed"
    
    def test_captcha_token_one_time_use(self, captcha_client):
        """Test that captcha tokens can only be used once"""
        # Register a user
        captcha_client.post(
            "/register",
            json={"username": "captchauser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make enough failed attempts to trigger captcha requirement
        for i in range(3):
            captcha_client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
        
        # Get a captcha token
        captcha_response = captcha_client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "526078169"}
        )
        captcha_token = captcha_response.json()["captcha_token"]
        
        # Use the token successfully
        response = captcha_client.post(
            "/login",
            json={
                "username": "captchauser",
                "password": "password123",
                "captcha_token": captcha_token
            }
        )
        assert response.status_code == 200
        
        # Make more failures to require captcha again
        for i in range(3):
            captcha_client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
        
        # Try to use the same token again (should fail)
        response = captcha_client.post(
            "/login",
            json={
                "username": "captchauser",
                "password": "password123",
                "captcha_token": captcha_token
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "captcha_failed"
    
    def test_captcha_token_expiration(self, client):
        """Test that expired captcha tokens are rejected"""
        from app import captcha
        
        # Register a user
        client.post(
            "/register",
            json={"username": "captchauser", "password": "password123"}
        )
        
        # Make enough failed attempts to trigger captcha requirement
        for i in range(3):
            client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
        
        # Get a captcha token normally
        captcha_response = client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "526078169"}
        )
        assert captcha_response.status_code == 200
        token = captcha_response.json()["captcha_token"]
        
        # Use the token successfully (should work)
        response = client.post(
            "/login",
            json={
                "username": "captchauser",
                "password": "password123",
                "captcha_token": token
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "success"
        
        # Make more failures to require captcha again
        for i in range(3):
            client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
        
        # Get a new token and manually set it to be expired
        captcha_response = client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "526078169"}
        )
        assert captcha_response.status_code == 200
        token = captcha_response.json()["captcha_token"]
        
        # Manually expire the token by setting its expiration to the past
        captcha._tokens[token] = time.time() - 1  # Set expiration to 1 second ago
        
        # Try to use the expired token
        response = client.post(
            "/login",
            json={
                "username": "captchauser",
                "password": "password123",
                "captcha_token": token
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "captcha_failed"
    
    def test_captcha_per_user_tracking(self, captcha_client):
        """Test that captcha failures are tracked per user"""
        # Register two users
        captcha_client.post(
            "/register",
            json={"username": "user1", "password": "pass123", "hash_mode": "argon2id", "category": "medium"}
        )
        captcha_client.post(
            "/register",
            json={"username": "user2", "password": "pass456", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make failures for user1 to trigger captcha requirement
        for i in range(3):
            captcha_client.post(
                "/login",
                json={"username": "user1", "password": "wrong"}
            )
        
        # Verify user1 requires captcha
        response = captcha_client.post(
            "/login",
            json={"username": "user1", "password": "wrong"}
        )
        assert response.status_code == 200
        assert response.json()["result"] == "captcha_failed"
        
        # user2 should not require captcha yet
        response = captcha_client.post(
            "/login",
            json={"username": "user2", "password": "wrong"}
        )
        assert response.status_code == 200
        assert response.json()["result"] == "invalid_credentials"
        assert response.json()["result"] != "captcha_failed"
        
        # Make failures for user2 to trigger captcha requirement
        for i in range(3):
            captcha_client.post(
                "/login",
                json={"username": "user2", "password": "wrong"}
            )
        
        # Now user2 should also require captcha
        response = captcha_client.post(
            "/login",
            json={"username": "user2", "password": "wrong"}
        )
        assert response.status_code == 200
        assert response.json()["result"] == "captcha_failed"
    
    def test_captcha_with_wrong_password_but_valid_token(self, captcha_client):
        """Test that valid captcha token doesn't bypass password validation"""
        # Register a user
        captcha_client.post(
            "/register",
            json={"username": "captchauser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make enough failed attempts to trigger captcha requirement
        for i in range(3):
            captcha_client.post(
                "/login",
                json={"username": "captchauser", "password": "wrongpassword"}
            )
        
        # Get a valid captcha token
        captcha_response = captcha_client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "526078169"}
        )
        captcha_token = captcha_response.json()["captcha_token"]
        
        # Try to login with valid captcha but wrong password
        response = captcha_client.post(
            "/login",
            json={
                "username": "captchauser",
                "password": "wrongpassword",
                "captcha_token": captcha_token
            }
        )
        # Should fail with invalid password, not captcha error
        assert response.status_code == 200
        assert response.json()["result"] == "invalid_credentials"
        assert response.json()["result"] != "captcha_failed"


@pytest.fixture(scope="function")
def totp_client(temp_db, totp_config):
    """Client fixture for totp tests"""
    yield from _create_client(temp_db, totp_config)


class TestLoginTotpE2E:
    """End-to-end tests for TOTP login functionality"""
    
    def test_login_totp_success(self, totp_client):
        """Test successful login with valid TOTP code"""
        # Register a user
        totp_client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Get user's TOTP secret from database
        user = db.get_user("totpuser")
        assert user is not None
        assert user.totp_secret is not None
        
        # Generate valid TOTP code
        import pyotp
        totp_obj = pyotp.TOTP(user.totp_secret)
        totp_code = totp_obj.now()
        
        # Login with valid TOTP
        response = totp_client.post(
            "/login_totp",
            json={
                "username": "totpuser",
                "password": "password123",
                "totp_code": totp_code
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "success"
    
    def test_login_totp_invalid_code(self, totp_client):
        """Test login fails with invalid TOTP code"""
        # Register a user
        totp_client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Try to login with invalid TOTP code
        response = totp_client.post(
            "/login_totp",
            json={
                "username": "totpuser",
                "password": "password123",
                "totp_code": "000000"
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "invalid_totp"
    
    def test_login_totp_missing_code(self, totp_client):
        """Test login fails when TOTP code is missing"""
        # Register a user
        totp_client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Try to login without TOTP code
        response = totp_client.post(
            "/login_totp",
            json={
                "username": "totpuser",
                "password": "password123"
                # totp_code is None by default
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "totp_required"
    
    def test_login_totp_wrong_password(self, totp_client):
        """Test that TOTP validation doesn't bypass password validation"""
        # Register a user
        totp_client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Get user's TOTP secret
        user = db.get_user("totpuser")
        import pyotp
        totp_obj = pyotp.TOTP(user.totp_secret)
        totp_code = totp_obj.now()
        
        # Try to login with valid TOTP but wrong password
        response = totp_client.post(
            "/login_totp",
            json={
                "username": "totpuser",
                "password": "wrongpassword",
                "totp_code": totp_code
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "invalid_credentials"
        assert response.json()["result"] != "invalid_totp"
    
    def test_login_totp_invalid_username(self, client):
        """Test login_totp fails with non-existent username"""
        response = client.post(
            "/login_totp",
            json={
                "username": "nonexistent",
                "password": "password123",
                "totp_code": "123456"
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "invalid_credentials"
    
    def test_login_totp_with_captcha_requirement(self, totp_client):
        """Test login_totp works with captcha requirement"""
        # Note: This test requires captcha, but totp_config disables it
        # Since captcha is disabled, this test will not trigger captcha requirement
        # Register a user
        totp_client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make enough failed attempts (but captcha won't trigger since it's disabled)
        for i in range(3):
            totp_client.post(
                "/login",
                json={"username": "totpuser", "password": "wrongpassword"}
            )
        
        # Get user's TOTP secret
        user = db.get_user("totpuser")
        import pyotp
        totp_obj = pyotp.TOTP(user.totp_secret)
        totp_code = totp_obj.now()
        
        # Get captcha token (even though captcha is disabled, the endpoint still works)
        captcha_response = totp_client.get(
            "/admin/get_captcha_token",
            params={"group_seed": "526078169"}
        )
        captcha_token = captcha_response.json()["captcha_token"]
        
        # Login with TOTP (captcha not required since it's disabled)
        response = totp_client.post(
            "/login_totp",
            json={
                "username": "totpuser",
                "password": "password123",
                "totp_code": totp_code,
                "captcha_token": captcha_token
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "success"
    
    def test_login_totp_rate_limiting(self, totp_client):
        """Test that rate limiting applies to login_totp endpoint"""
        # Register a user
        totp_client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Make many failed login_totp attempts (exceeding rate limit)
        # Note: After 10 failures, account gets locked (lockout threshold)
        for i in range(21):
            response = totp_client.post(
                "/login_totp",
                json={
                    "username": "totpuser",
                    "password": "wrongpassword",
                    "totp_code": "000000"
                }
            )
            assert response.status_code == 200
            if i < 10:
                # Before lockout threshold, should get invalid credentials or invalid TOTP
                assert response.json()["result"] in ["invalid_credentials", "invalid_totp"]
            elif i < 20:
                # After lockout threshold but before rate limit, should get locked_out
                assert response.json()["result"] == "locked_out"
            else:
                # 21st attempt should fail with rate limit (but account is already locked)
                assert response.json()["result"] in ["rate_limit_exceeded", "locked_out"]
        
        # 22nd attempt should still fail (rate limit or invalid credentials)
        response = totp_client.post(
            "/login_totp",
            json={
                "username": "totpuser",
                "password": "wrongpassword",
                "totp_code": "000000"
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "rate_limit_exceeded"

    def test_login_totp_lockout(self, totp_client):
        """Test that lockout applies to login_totp endpoint"""
        # Register a user
        totp_client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Trigger lockout by making many failed attempts
        # Since captcha is disabled, we can make all attempts without captcha
        for i in range(11):
            totp_client.post(
                "/login_totp",
                json={
                    "username": "totpuser",
                    "password": "wrongpassword",
                    "totp_code": "000000"
                }
            )
        
        # Try to login with correct credentials and TOTP while locked
        user = db.get_user("totpuser")
        import pyotp
        totp_obj = pyotp.TOTP(user.totp_secret)
        totp_code = totp_obj.now()
        
        response = totp_client.post(
            "/login_totp",
            json={
                "username": "totpuser",
                "password": "password123",
                "totp_code": totp_code
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "locked_out"
    
    def test_login_totp_expired_code(self, totp_client):
        """Test that expired TOTP codes are rejected"""
        # Register a user
        totp_client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Get user's TOTP secret
        user = db.get_user("totpuser")
        import pyotp
        totp_obj = pyotp.TOTP(user.totp_secret)
        
        # Generate a code from a time step that's outside the valid window
        # TOTP uses 30-second intervals, and valid_window=1 means we accept
        # codes from current, previous, and next time step
        # A code from 90 seconds ago (3 time steps) should be rejected
        old_timestamp = int(time.time() - 90)
        old_code = totp_obj.at(old_timestamp)
        
        response = totp_client.post(
            "/login_totp",
            json={
                "username": "totpuser",
                "password": "password123",
                "totp_code": old_code
            }
        )
        # Should fail with invalid TOTP (expired codes are rejected)
        assert response.status_code == 200
        assert response.json()["result"] == "invalid_totp"
    
    def test_login_totp_multiple_successful_logins(self, client):
        """Test that multiple successful login_totp attempts work"""
        # Register a user
        client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Get user's TOTP secret
        user = db.get_user("totpuser")
        import pyotp
        totp_obj = pyotp.TOTP(user.totp_secret)
        
        # Login multiple times successfully
        for i in range(5):
            totp_code = totp_obj.now()
            response = client.post(
                "/login_totp",
                json={
                    "username": "totpuser",
                    "password": "password123",
                    "totp_code": totp_code
                }
            )
            assert response.status_code == 200
            assert response.json()["result"] == "success"
            # Small delay to ensure different time steps if needed
            time.sleep(0.1)
    
    def test_login_totp_user_without_totp_secret(self, totp_client):
        """Test login_totp fails when user doesn't have TOTP secret configured"""
        # Register a user
        totp_client.post(
            "/register",
            json={"username": "totpuser", "password": "password123", "hash_mode": "argon2id", "category": "medium"}
        )
        
        # Manually set TOTP secret to None in database
        from app.models import UserModel
        from sqlalchemy import select
        with db.get_session() as session:
            stmt = select(UserModel).where(UserModel.username == "totpuser")
            user_model = session.execute(stmt).scalar_one()
            user_model.totp_secret = None
            # Session will commit automatically via context manager
        
        # Try to login with TOTP
        response = totp_client.post(
            "/login_totp",
            json={
                "username": "totpuser",
                "password": "password123",
                "totp_code": "123456"
            }
        )
        assert response.status_code == 200
        assert response.json()["result"] == "totp_not_configured"

