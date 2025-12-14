import pytest
import sys
import os
from unittest.mock import patch
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app import captcha


class TestCaptcha:
    """Test suite for Captcha module"""

    def setup_method(self):
        """Reset the internal tokens dictionary before each test"""
        captcha._tokens.clear()

    def test_issue_captcha_returns_token_and_ttl(self):
        """Test that issue_captcha returns a token and TTL"""
        token, ttl = captcha.issue_captcha(ttl_s=300)
        
        assert isinstance(token, str)
        assert len(token) > 0
        assert ttl == 300

    def test_issue_captcha_generates_unique_tokens(self):
        """Test that each call to issue_captcha generates a unique token"""
        token1, _ = captcha.issue_captcha(ttl_s=300)
        token2, _ = captcha.issue_captcha(ttl_s=300)
        token3, _ = captcha.issue_captcha(ttl_s=300)
        
        assert token1 != token2
        assert token2 != token3
        assert token1 != token3

    def test_issue_captcha_stores_token(self):
        """Test that issue_captcha stores the token internally"""
        token, ttl = captcha.issue_captcha(ttl_s=300)
        
        assert token in captcha._tokens
        assert isinstance(captcha._tokens[token], float)

    def test_verify_captcha_returns_true_for_valid_token(self):
        """Test that verify_captcha returns True for a valid, non-expired token"""
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            token, _ = captcha.issue_captcha(ttl_s=300)
            # Token expires at 1000 + 300 = 1300
            
            # Verify at time 1200 (still valid)
            mock_time.return_value = 1200.0
            result = captcha.verify_captcha(token)
            
            assert result == True

    def test_verify_captcha_returns_false_for_invalid_token(self):
        """Test that verify_captcha returns False for an unknown token"""
        result = captcha.verify_captcha("invalid_token_12345")
        
        assert result == False

    def test_verify_captcha_returns_false_for_expired_token(self):
        """Test that verify_captcha returns False for an expired token"""
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            token, _ = captcha.issue_captcha(ttl_s=300)
            # Token expires at 1000 + 300 = 1300
            
            # Verify at time 1301 (expired)
            mock_time.return_value = 1301.0
            result = captcha.verify_captcha(token)
            
            assert result == False
            # Expired token should be removed
            assert token not in captcha._tokens

    def test_verify_captcha_removes_token_after_verification(self):
        """Test that verify_captcha removes the token after successful verification (one-time use)"""
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            token, _ = captcha.issue_captcha(ttl_s=300)
            assert token in captcha._tokens
            
            # First verification should succeed
            mock_time.return_value = 1200.0
            result1 = captcha.verify_captcha(token)
            assert result1 == True
            
            # Token should be removed after verification
            assert token not in captcha._tokens
            
            # Second verification should fail (token no longer exists)
            result2 = captcha.verify_captcha(token)
            assert result2 == False

    def test_verify_captcha_at_expiration_boundary(self):
        """Test that verify_captcha handles the exact expiration time correctly"""
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            token, _ = captcha.issue_captcha(ttl_s=300)
            # Token expires at 1000 + 300 = 1300
            
            # Verify at exactly expiration time (1300.0)
            mock_time.return_value = 1300.0
            result = captcha.verify_captcha(token)
            
            # At exactly expiration time, token should still be valid (> comparison)
            assert result == True

    def test_verify_captcha_just_after_expiration(self):
        """Test that verify_captcha correctly identifies tokens just after expiration"""
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            token, _ = captcha.issue_captcha(ttl_s=300)
            # Token expires at 1000 + 300 = 1300
            
            # Verify just after expiration (1300.000001)
            mock_time.return_value = 1300.000001
            result = captcha.verify_captcha(token)
            
            assert result == False
            assert token not in captcha._tokens

    def test_multiple_tokens_independent(self):
        """Test that multiple tokens can be issued and verified independently"""
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            token1, _ = captcha.issue_captcha(ttl_s=300)
            token2, _ = captcha.issue_captcha(ttl_s=600)
            token3, _ = captcha.issue_captcha(ttl_s=100)
            
            # Verify first token at time 1200 (valid)
            mock_time.return_value = 1200.0
            assert captcha.verify_captcha(token1) == True
            
            # Verify second token at time 1500 (valid)
            mock_time.return_value = 1500.0
            assert captcha.verify_captcha(token2) == True
            
            # Third token should be expired at time 1101
            mock_time.return_value = 1101.0
            assert captcha.verify_captcha(token3) == False

    def test_empty_token_string(self):
        """Test that verify_captcha handles empty token string"""
        result = captcha.verify_captcha("")
        assert result == False

    def test_none_token(self):
        """Test that verify_captcha handles None token"""
        # None token should return False (token not found in dictionary)
        result = captcha.verify_captcha(None)
        assert result == False

    def test_issue_captcha_with_zero_ttl(self):
        """Test that issue_captcha handles zero TTL correctly"""
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            token, ttl = captcha.issue_captcha(ttl_s=0)
            assert ttl == 0
            
            # Token should expire immediately
            mock_time.return_value = 1000.000001
            result = captcha.verify_captcha(token)
            assert result == False

    def test_issue_captcha_with_negative_ttl(self):
        """Test that issue_captcha handles negative TTL (should still create token)"""
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            token, ttl = captcha.issue_captcha(ttl_s=-100)
            assert ttl == -100
            
            # Token should be expired immediately since expiration is in the past
            mock_time.return_value = 1000.0
            result = captcha.verify_captcha(token)
            assert result == False

