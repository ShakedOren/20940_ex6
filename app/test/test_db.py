import pytest
import sqlite3
import os
import tempfile
from unittest.mock import patch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import db


@pytest.fixture
def temp_db():
    fd, temp_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    
    with patch.object(db, 'db_path', temp_path):
        db.init_db(temp_path)
        yield temp_path
    
    if os.path.exists(temp_path):
        os.remove(temp_path)


def test_create_user(temp_db):
    """Test creating a user"""
    with patch.object(db, 'db_path', temp_db):
        db.create_user("testuser", "hashed_password")
        
        # Verify user was created
        user = db.get_user("testuser")
        assert user is not None
        assert user[1] == "testuser"
        assert user[2] == "hashed_password"


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
        assert user[1] == "newuser"
        assert user[2] == "password123"
