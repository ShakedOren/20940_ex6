import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app.rate_limit import RateLimiter
from unittest.mock import patch
import time


class TestRateLimiter:
    """Test suite for RateLimiter class"""

    def test_initial_state(self):
        """Test that RateLimiter initializes correctly"""
        limiter = RateLimiter(attempts=5, sliding_window=60)
        assert limiter.attempts == 5
        assert limiter.sliding_window == 60
        assert limiter.buckets == {}

    def test_allows_attempts_within_limit(self):
        """Test that rate limiter allows attempts up to the limit"""
        limiter = RateLimiter(attempts=3, sliding_window=60)
        
        # First 3 attempts should be allowed
        assert limiter.check("user1") == True
        assert limiter.check("user1") == True
        assert limiter.check("user1") == True

    def test_blocks_after_limit_exceeded(self):
        """Test that rate limiter blocks after exceeding the limit"""
        limiter = RateLimiter(attempts=2, sliding_window=60)
        
        # First 2 attempts should be allowed
        assert limiter.check("user1") == True
        assert limiter.check("user1") == True
        
        # 3rd attempt should be blocked
        assert limiter.check("user1") == False

    def test_sliding_window_expiration(self):
        """Test that old attempts expire outside the sliding window"""
        limiter = RateLimiter(attempts=2, sliding_window=60)
        
        with patch('time.time') as mock_time:
            # Start at time 100
            mock_time.return_value = 100.0
            
            # Make 2 attempts at time 100
            assert limiter.check("user1") == True
            assert limiter.check("user1") == True
            
            # Should be blocked at time 100
            assert limiter.check("user1") == False
            
            # Move to time 161 (61 seconds later, outside the 60s window)
            mock_time.return_value = 161.0
            
            # Should now be allowed again (old attempts expired)
            assert limiter.check("user1") == True

    def test_sliding_window_partial_expiration(self):
        """Test that only old attempts outside the window are removed"""
        limiter = RateLimiter(attempts=3, sliding_window=60)
        
        with patch('time.time') as mock_time:
            # Start at time 100
            mock_time.return_value = 100.0
            assert limiter.check("user1") == True  # Added at 100
            
            mock_time.return_value = 120.0
            assert limiter.check("user1") == True  # Added at 120
            
            mock_time.return_value = 140.0
            assert limiter.check("user1") == True  # Added at 140
            
            # All 3 attempts used, should be blocked
            assert limiter.check("user1") == False
            
            # Move to time 161 (only first attempt at 100 expires)
            mock_time.return_value = 161.0
            assert limiter.check("user1") == True  # Should be allowed (1 expired, 2 remaining)
            
            # Move to time 181 (first two attempts expire)
            mock_time.return_value = 181.0
            assert limiter.check("user1") == True  # Should be allowed (2 expired, 1 remaining)

    def test_multiple_keys_separate_buckets(self):
        """Test that different keys have separate rate limit buckets"""
        limiter = RateLimiter(attempts=2, sliding_window=60)
        
        # Exhaust limit for user1
        assert limiter.check("user1") == True
        assert limiter.check("user1") == True
        assert limiter.check("user1") == False  # user1 blocked
        
        # user2 should still be allowed
        assert limiter.check("user2") == True
        assert limiter.check("user2") == True
        assert limiter.check("user2") == False  # user2 now blocked

    def test_bucket_cleanup_on_check(self):
        """Test that old timestamps are removed from bucket when checking"""
        limiter = RateLimiter(attempts=2, sliding_window=60)
        
        with patch('time.time') as mock_time:
            # Make attempts at different times
            mock_time.return_value = 100.0
            assert limiter.check("user1") == True
            
            mock_time.return_value = 120.0
            assert limiter.check("user1") == True
            
            # Verify bucket has 2 entries
            assert len(limiter.buckets["user1"]) == 2
            
            # Move far into the future
            mock_time.return_value = 300.0
            
            # This check should remove both old entries
            assert limiter.check("user1") == True
            
            # Bucket should now have only 1 entry (the new one)
            assert len(limiter.buckets["user1"]) == 1

    def test_edge_case_exactly_at_window_boundary(self):
        """Test behavior when timestamp is exactly at window boundary"""
        limiter = RateLimiter(attempts=2, sliding_window=60)
        
        with patch('time.time') as mock_time:
            mock_time.return_value = 100.0
            assert limiter.check("user1") == True
            
            # At exactly 160 (100 + 60), the attempt should expire
            mock_time.return_value = 160.0
            assert limiter.check("user1") == True  # Should still be in window
            
            # At 160.1, the first attempt should be expired
            mock_time.return_value = 160.1
            # The first attempt at 100 should be removed (100 < 160.1 - 60 = 100.1)
            assert limiter.check("user1") == True  # Should allow (old one expired)

    def test_zero_attempts_limit(self):
        """Test behavior with zero attempts limit"""
        limiter = RateLimiter(attempts=0, sliding_window=60)
        
        # Should always be blocked
        assert limiter.check("user1") == False

    def test_single_attempt_limit(self):
        """Test behavior with single attempt limit"""
        limiter = RateLimiter(attempts=1, sliding_window=60)
        
        assert limiter.check("user1") == True
        assert limiter.check("user1") == False

    def test_rapid_successive_attempts(self):
        """Test handling of rapid successive attempts"""
        limiter = RateLimiter(attempts=5, sliding_window=60)
        
        with patch('time.time') as mock_time:
            # Make 5 rapid attempts
            for i in range(5):
                mock_time.return_value = 100.0 + i * 0.001  # Very close timestamps
                assert limiter.check("user1") == True
            
            # 6th attempt should be blocked
            mock_time.return_value = 100.006
            assert limiter.check("user1") == False

