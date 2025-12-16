import pytest
import sqlite3
import os
import tempfile
import time
import gc
from unittest.mock import patch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app.models import User
from app import db
from app.security import verify_password, get_pepper

@pytest.fixture
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
        # Dispose of SQLAlchemy engine to close all connections
        if db.engine is not None:
            db.engine.dispose()
        
        # Close any open connections by forcing garbage collection
        gc.collect()
        
        # On Windows, give the OS time to release file handles
        if os.name == 'nt':
            time.sleep(0.1)
        
        # Try to close any lingering connections
        try:
            # Force close any open sqlite3 connections
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


def test_create_user(temp_db):
    """Test creating a user"""
    with patch.object(db, 'db_path', temp_db):
        db.create_user("testuser", "password")
        
        # Verify user was created
        user = db.get_user("testuser")
        assert user is not None
        assert user.username == "testuser"
        # Password should be hashed, not plain text
        assert user.password != "password"
        assert verify_password("password", user.salt, get_pepper(), user.password, "argon2id") == True


def test_get_user_nonexistent(temp_db):
    """Test getting a non-existent user"""
    with patch.object(db, 'db_path', temp_db):
        user = db.get_user("nonexistent")
        assert user is None


def test_create_and_get_user(temp_db):
    """Test creating a user and then getting it"""
    with patch.object(db, 'db_path', temp_db):
        db.create_user("newuser", "password123")
        user = db.get_user("newuser")
        
        assert user is not None
        assert user.username == "newuser"
        # Password should be hashed, verify it matches
        assert verify_password("password123", user.salt, get_pepper(), user.password, "argon2id") == True
        # Verify wrong password fails
        assert verify_password("wrongpassword", user.salt, get_pepper(), user.password, "argon2id") == False
