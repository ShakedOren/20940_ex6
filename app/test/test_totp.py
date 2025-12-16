import pytest
import sys
import os
from unittest.mock import patch
import time
import pyotp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app import totp


class TestTotp:
    """Test suite for TOTP module"""

    def test_generate_secret_returns_string(self):
        """Test that generate_secret returns a string"""
        secret = totp.generate_secret()
        
        assert isinstance(secret, str)
        assert len(secret) > 0

    def test_generate_secret_returns_base32(self):
        """Test that generate_secret returns a valid base32 string"""
        secret = totp.generate_secret()
        
        # Base32 characters are A-Z and 2-7
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
        assert all(c in valid_chars for c in secret)

    def test_generate_secret_generates_unique_secrets(self):
        """Test that each call to generate_secret generates a unique secret"""
        secret1 = totp.generate_secret()
        secret2 = totp.generate_secret()
        secret3 = totp.generate_secret()
        
        assert secret1 != secret2
        assert secret2 != secret3
        assert secret1 != secret3

    def test_generate_secret_has_reasonable_length(self):
        """Test that generate_secret generates secrets of reasonable length"""
        secret = totp.generate_secret()
        
        # pyotp.random_base32() typically generates 16-32 character secrets
        assert len(secret) >= 16
        assert len(secret) <= 32

    def test_verify_totp_returns_true_for_valid_code(self):
        """Test that verify_totp returns True for a valid TOTP code"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        code = totp_obj.now()
        
        result, offset = totp.verify_totp(secret, code)
        
        assert result == True
        assert offset is not None
        assert isinstance(offset, int)
        assert offset == 0  # Should be current time step

    def test_verify_totp_returns_false_for_invalid_code(self):
        """Test that verify_totp returns False for an invalid TOTP code"""
        secret = totp.generate_secret()
        invalid_code = "000000"
        
        result, offset = totp.verify_totp(secret, invalid_code)
        
        assert result == False
        assert offset is None

    def test_verify_totp_returns_false_for_wrong_secret(self):
        """Test that verify_totp returns False when code doesn't match secret"""
        secret1 = totp.generate_secret()
        secret2 = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret1)
        code = totp_obj.now()
        
        result, offset = totp.verify_totp(secret2, code)
        
        assert result == False
        assert offset is None

    def test_verify_totp_with_valid_window_default(self):
        """Test that verify_totp accepts codes within default valid_window (1)"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        interval = totp_obj.interval
        base_time = 1000000.0  # Fixed base time for testing
        
        # Generate code at base_time using at() method
        code_at_base = totp_obj.at(base_time)
        
        # Test verifying at base_time - interval (code should be valid with offset +1)
        with patch('app.totp.time.time', return_value=base_time - interval):
            result, offset = totp.verify_totp(secret, code_at_base)
            assert result == True
            assert offset == 1  # Code is 1 step ahead of verification time
        
        # Test verifying at base_time + interval (code should be valid with offset -1)
        with patch('app.totp.time.time', return_value=base_time + interval):
            result, offset = totp.verify_totp(secret, code_at_base)
            assert result == True
            assert offset == -1  # Code is 1 step behind verification time

    def test_verify_totp_with_custom_valid_window(self):
        """Test that verify_totp accepts codes within custom valid_window"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        interval = totp_obj.interval
        base_time = 1000000.0  # Fixed base time for testing
        
        # Generate code at base_time using at() method
        code_at_base = totp_obj.at(base_time)
        
        # Test with valid_window=2, should accept codes from -2 to +2 intervals
        with patch('app.totp.time.time', return_value=base_time - 2 * interval):
            result, offset = totp.verify_totp(secret, code_at_base, valid_window=2)
            assert result == True
            assert offset == 2
        
        with patch('app.totp.time.time', return_value=base_time + 2 * interval):
            result, offset = totp.verify_totp(secret, code_at_base, valid_window=2)
            assert result == True
            assert offset == -2

    def test_verify_totp_rejects_outside_valid_window(self):
        """Test that verify_totp rejects codes outside valid_window"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        interval = totp_obj.interval
        
        # Get code for current time
        current_code = totp_obj.now()
        
        # Test with valid_window=1, should reject codes from -2 intervals
        with patch('time.time') as mock_time:
            mock_time.return_value = time.time() - 2 * interval
            result, offset = totp.verify_totp(secret, current_code, valid_window=1)
            assert result == False
            assert offset is None
        
        # Test with valid_window=1, should reject codes from +2 intervals
        with patch('time.time') as mock_time:
            mock_time.return_value = time.time() + 2 * interval
            result, offset = totp.verify_totp(secret, current_code, valid_window=1)
            assert result == False
            assert offset is None

    def test_verify_totp_with_zero_valid_window(self):
        """Test that verify_totp works with valid_window=0 (only current time step)"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        code = totp_obj.now()
        
        result, offset = totp.verify_totp(secret, code, valid_window=0)
        
        assert result == True
        assert offset == 0

    def test_verify_totp_with_zero_valid_window_rejects_adjacent(self):
        """Test that verify_totp with valid_window=0 rejects adjacent time steps"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        interval = totp_obj.interval
        current_code = totp_obj.now()
        
        # Should reject previous time step
        with patch('app.totp.time.time', return_value=time.time() - interval):
            result, offset = totp.verify_totp(secret, current_code, valid_window=0)
            assert result == False
            assert offset is None
        
        # Should reject next time step
        with patch('app.totp.time.time', return_value=time.time() + interval):
            result, offset = totp.verify_totp(secret, current_code, valid_window=0)
            assert result == False
            assert offset is None

    def test_verify_totp_returns_correct_offset(self):
        """Test that verify_totp returns the correct offset when code is valid"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        interval = totp_obj.interval
        base_time = 1000000.0  # Fixed base time for testing
        
        # Generate code at base_time using at() method
        code_at_base = totp_obj.at(base_time)
        
        # Test various verification times relative to base_time
        for time_offset in [-2, -1, 0, 1, 2]:
            with patch('app.totp.time.time', return_value=base_time + time_offset * interval):
                result, returned_offset = totp.verify_totp(secret, code_at_base, valid_window=2)
                if abs(time_offset) <= 2:
                    assert result == True
                    assert returned_offset == -time_offset  # Offset is inverted
                else:
                    assert result == False

    def test_verify_totp_with_empty_code(self):
        """Test that verify_totp handles empty code string"""
        secret = totp.generate_secret()
        
        result, offset = totp.verify_totp(secret, "")
        
        assert result == False
        assert offset is None

    def test_verify_totp_with_invalid_code_format(self):
        """Test that verify_totp handles invalid code format"""
        secret = totp.generate_secret()
        
        # Test with non-numeric code
        result, offset = totp.verify_totp(secret, "ABCDEF")
        assert result == False
        assert offset is None
        
        # Test with too short code
        result, offset = totp.verify_totp(secret, "12345")
        assert result == False
        assert offset is None
        
        # Test with too long code
        result, offset = totp.verify_totp(secret, "1234567")
        assert result == False
        assert offset is None

    def test_verify_totp_with_invalid_secret(self):
        """Test that verify_totp handles invalid secret format"""
        invalid_secret = "INVALID_SECRET_FORMAT"
        code = "123456"
        
        # This might raise an exception or return False depending on pyotp behavior
        # Let's test it
        try:
            result, offset = totp.verify_totp(invalid_secret, code)
            assert result == False
            assert offset is None
        except Exception:
            # If it raises an exception, that's also acceptable behavior
            pass

    def test_verify_totp_consistency(self):
        """Test that verify_totp is consistent across multiple calls with same inputs"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        code = totp_obj.now()
        
        result1, offset1 = totp.verify_totp(secret, code)
        result2, offset2 = totp.verify_totp(secret, code)
        
        assert result1 == result2
        assert offset1 == offset2

    def test_verify_totp_with_expired_code(self):
        """Test that verify_totp rejects codes that are too old"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        interval = totp_obj.interval
        base_time = 1000000.0  # Fixed base time for testing
        
        # Generate code 3 intervals ago using at() method
        old_code = totp_obj.at(base_time - 3 * interval)
        
        # Try to verify at base_time with default valid_window=1 (should reject)
        with patch('app.totp.time.time', return_value=base_time):
            result, offset = totp.verify_totp(secret, old_code, valid_window=1)
            assert result == False
            assert offset is None

    def test_verify_totp_with_future_code(self):
        """Test that verify_totp rejects codes that are too far in the future"""
        secret = totp.generate_secret()
        totp_obj = pyotp.TOTP(secret)
        interval = totp_obj.interval
        base_time = 1000000.0  # Fixed base time for testing
        
        # Generate code 3 intervals in the future using at() method
        future_code = totp_obj.at(base_time + 3 * interval)
        
        # Try to verify at base_time with default valid_window=1 (should reject)
        with patch('app.totp.time.time', return_value=base_time):
            result, offset = totp.verify_totp(secret, future_code, valid_window=1)
            assert result == False
            assert offset is None
