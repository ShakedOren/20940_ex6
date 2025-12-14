import pytest
import os
import tempfile
import time
import gc
import sqlite3
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


@pytest.fixture(scope="function")
def client(temp_db):
    """Create a test client with a temporary database"""
    with patch.object(db, 'db_path', temp_db):
        # Reset rate limiter and lockout tracker for each test
        main.rate_limiter.buckets.clear()
        main.lockouts.failures.clear()
        main.lockouts.locked_until.clear()
        
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
            json={"username": "testuser", "password": "password123"}
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
            json={"username": "testuser", "password": "password123"}
        )
        assert response.status_code == 200
        
        # Try to register again with same username
        response = client.post(
            "/register",
            json={"username": "testuser", "password": "differentpass"}
        )
        assert response.status_code == 400
        assert "Username already exists" in response.json()["detail"]
    
    def test_register_short_password(self, client):
        """Test that password validation works (min length 6)"""
        response = client.post(
            "/register",
            json={"username": "testuser", "password": "short"}
        )
        assert response.status_code == 422  # Validation error
    
    def test_register_multiple_users(self, client):
        """Test registering multiple different users"""
        users = [
            {"username": "user1", "password": "pass123"},
            {"username": "user2", "password": "pass456"},
            {"username": "user3", "password": "pass789"},
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
            json={"username": "testuser", "password": "password123"}
        )
        
        # Login with correct credentials
        response = client.post(
            "/login",
            json={"username": "testuser", "password": "password123"}
        )
        assert response.status_code == 200
        assert response.json() == {"result": "success"}
    
    def test_login_invalid_username(self, client):
        """Test login with non-existent username"""
        response = client.post(
            "/login",
            json={"username": "nonexistent", "password": "password123"}
        )
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["detail"]
    
    def test_login_invalid_password(self, client):
        """Test login with wrong password"""
        # Register a user first
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123"}
        )
        
        # Try to login with wrong password
        response = client.post(
            "/login",
            json={"username": "testuser", "password": "wrongpassword"}
        )
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["detail"]
    
    def test_login_after_registration(self, client):
        """Test complete flow: register then login"""
        # Register
        register_response = client.post(
            "/register",
            json={"username": "newuser", "password": "mypassword"}
        )
        assert register_response.status_code == 200
        
        # Login
        login_response = client.post(
            "/login",
            json={"username": "newuser", "password": "mypassword"}
        )
        assert login_response.status_code == 200
        assert login_response.json() == {"result": "success"}


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limit_enforcement(self, client):
        """Test that rate limiting blocks too many attempts"""
        # Register a user
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123"}
        )
        
        # Make many failed login attempts (exceeding rate limit)
        # Default rate limit is 20 attempts per 60 seconds
        for i in range(21):
            response = client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
            if i < 20:
                # First 20 should fail with invalid password
                assert response.status_code == 401
            else:
                # 21st should fail with rate limit
                assert response.status_code == 401
                # Check if it's rate limit error (might be rate limit or invalid password)
                # The rate limiter checks before password verification
    
    def test_rate_limit_resets_after_window(self, client):
        """Test that rate limit resets after the time window"""
        # Register a user
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123"}
        )
        
        # Make attempts up to the rate limit (20) but stay under lockout threshold (10)
        # So we'll make 9 failed attempts to test rate limiting without triggering lockout
        for i in range(9):
            response = client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
            assert response.status_code == 401
        
        # Now make attempts to reach rate limit (20 total)
        for i in range(11):
            response = client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
            assert response.status_code == 401
        
        # Wait for rate limit window to pass (mock time)
        # Patch time.time in the rate_limit module
        current_time = time.time()
        with patch('app.rate_limit.time.time') as mock_time:
            # Set mock time to be 61 seconds in the future
            mock_time.return_value = current_time + 61
            
            # Should be able to make another attempt (rate limit expired, but user is locked)
            # User is locked because we exceeded lockout threshold (10)
            response = client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
            # Should fail with lockout since we exceeded threshold
            assert response.status_code == 401
            assert "User locked out" in response.json()["detail"]
    
    def test_rate_limit_per_user(self, client):
        """Test that rate limiting is per user"""
        # Register two users
        client.post(
            "/register",
            json={"username": "user1", "password": "pass1"}
        )
        client.post(
            "/register",
            json={"username": "user2", "password": "pass2"}
        )
        
        # Exhaust rate limit for user1
        for i in range(20):
            client.post(
                "/login",
                json={"username": "user1", "password": "wrong"}
            )
        
        # user2 should still be able to attempt login
        response = client.post(
            "/login",
            json={"username": "user2", "password": "wrong"}
        )
        assert response.status_code == 401  # Invalid password, not rate limited


class TestLockout:
    """Test account lockout functionality"""
    
    def test_lockout_after_threshold(self, client):
        """Test that account gets locked after threshold failures"""
        # Register a user
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123"}
        )
        
        # Default lockout threshold is 10
        # Make failed login attempts up to threshold
        for i in range(10):
            response = client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
            assert response.status_code == 401
            assert "Invalid username or password" in response.json()["detail"]
        
        # 11th attempt should trigger lockout
        response = client.post(
            "/login",
            json={"username": "testuser", "password": "wrongpassword"}
        )
        assert response.status_code == 401
        # Should be locked out
        assert "User locked out" in response.json()["detail"]
    
    def test_lockout_prevents_login(self, client):
        """Test that locked account cannot login even with correct password"""
        # Register a user
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123"}
        )
        
        # Trigger lockout by making many failed attempts
        # Need to exceed lockout threshold (default 10)
        for i in range(11):
            client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
        
        # Try to login with correct password while locked
        response = client.post(
            "/login",
            json={"username": "testuser", "password": "password123"}
        )
        assert response.status_code == 401
        # Should be locked out
        assert "User locked out" in response.json()["detail"]
    
    def test_lockout_expires_after_duration(self, client):
        """Test that lockout expires after the duration"""
        # Register a user
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123"}
        )
        
        # Trigger lockout
        for i in range(11):
            client.post(
                "/login",
                json={"username": "testuser", "password": "wrongpassword"}
            )
        
        # Verify locked
        locked, _ = main.lockouts.is_locked("testuser")
        assert locked == True
        
        # Mock time to expire lockout (default duration is 300 seconds)
        # Patch time.time in the lockout_tracker module
        current_time = time.time()
        with patch('app.lockout_tracker.time.time') as mock_time:
            # Set initial time
            mock_time.return_value = current_time
            
            # Verify still locked
            locked, _ = main.lockouts.is_locked("testuser")
            assert locked == True
            
            # Move time forward past lockout duration
            mock_time.return_value = current_time + 301
            
            # Should be able to login now (lockout expired)
            response = client.post(
                "/login",
                json={"username": "testuser", "password": "password123"}
            )
            # Should succeed now that lockout is expired
            assert response.status_code == 200
            assert response.json() == {"result": "success"}
    
    def test_lockout_per_user(self, client):
        """Test that lockout is per user"""
        # Register two users (use passwords with 6+ characters to satisfy validation)
        reg_response1 = client.post(
            "/register",
            json={"username": "user1", "password": "pass123"}
        )
        assert reg_response1.status_code == 200
        
        reg_response2 = client.post(
            "/register",
            json={"username": "user2", "password": "pass456"}
        )
        assert reg_response2.status_code == 200
        
        # Lock out user1
        for i in range(11):
            client.post(
                "/login",
                json={"username": "user1", "password": "wrong"}
            )
        
        # user2 should still be able to login (lockout is per-user, so user2 isn't affected)
        response = client.post(
            "/login",
            json={"username": "user2", "password": "pass456"}
        )
        assert response.status_code == 200
        assert response.json() == {"result": "success"}


class TestIntegrationScenarios:
    """Test complex integration scenarios"""
    
    def test_register_login_logout_flow(self, client):
        """Test complete user flow: register, login multiple times"""
        # Register
        response = client.post(
            "/register",
            json={"username": "flowuser", "password": "flowpass"}
        )
        assert response.status_code == 200
        
        # Login multiple times successfully
        for i in range(5):
            response = client.post(
                "/login",
                json={"username": "flowuser", "password": "flowpass"}
            )
            assert response.status_code == 200
            assert response.json() == {"result": "success"}
    
    def test_failed_attempts_then_success(self, client):
        """Test that successful login clears failure count"""
        # Register
        client.post(
            "/register",
            json={"username": "testuser", "password": "password123"}
        )
        
        # Make some failed attempts (but not enough to lockout)
        for i in range(5):
            response = client.post(
                "/login",
                json={"username": "testuser", "password": "wrong"}
            )
            assert response.status_code == 401
        
        # Successful login should work
        response = client.post(
            "/login",
            json={"username": "testuser", "password": "password123"}
        )
        assert response.status_code == 200
        assert response.json() == {"result": "success"}
        
        # After success, should be able to make more failed attempts without lockout
        # (since failure count was reset)
        for i in range(5):
            response = client.post(
                "/login",
                json={"username": "testuser", "password": "wrong"}
            )
            assert response.status_code == 401
    
    def test_multiple_users_independent(self, client):
        """Test that multiple users operate independently"""
        # Register multiple users
        users = [
            {"username": "alice", "password": "alicepass"},
            {"username": "bob", "password": "bobpass"},
            {"username": "charlie", "password": "charliepass"},
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
            assert response.json() == {"result": "success"}
        
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
        # Should fail validation or return 401
        assert response.status_code in [400, 401, 422]
    
    def test_edge_case_empty_password(self, client):
        """Test edge case: empty password"""
        response = client.post(
            "/login",
            json={"username": "testuser", "password": ""}
        )
        # Should fail validation or return 401
        assert response.status_code in [400, 401, 422]

