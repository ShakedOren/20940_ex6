import pytest
import sys
import os
from unittest.mock import patch
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app.lockout_tracker import LockoutTracker


class TestLockoutTracker:
    """Test suite for LockoutTracker class"""

    def test_initial_state(self):
        """Test that LockoutTracker initializes correctly"""
        tracker = LockoutTracker(threshold=5, duration_s=300)
        assert tracker.threshold == 5
        assert tracker.duration_s == 300
        assert tracker.failures == {}
        assert tracker.locked_until == {}

    def test_is_locked_returns_false_for_new_key(self):
        """Test that a new key is not locked"""
        tracker = LockoutTracker(threshold=3, duration_s=60)
        locked, remaining = tracker.is_locked("user1")
        assert locked == False
        assert remaining == 0

    def test_record_failure_below_threshold(self):
        """Test recording failures below the threshold"""
        tracker = LockoutTracker(threshold=3, duration_s=60)
        
        # Record 2 failures (below threshold)
        tracker.record_failure("user1")
        tracker.record_failure("user1")
        
        # Should not be locked
        locked, remaining = tracker.is_locked("user1")
        assert locked == False
        assert tracker.failures["user1"] == 2

    def test_lockout_after_threshold_reached(self):
        """Test that lockout occurs after threshold is reached"""
        tracker = LockoutTracker(threshold=3, duration_s=300)
        
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            # Record failures up to threshold
            tracker.record_failure("user1")
            tracker.record_failure("user1")
            tracker.record_failure("user1")  # 3rd failure triggers lockout
            
            # Should be locked
            locked, remaining = tracker.is_locked("user1")
            assert locked == True
            assert remaining == 300  # Full duration remaining
            # Failures should be reset after lockout
            assert tracker.failures.get("user1", 0) == 0

    def test_lockout_expires_after_duration(self):
        """Test that lockout expires after the duration"""
        tracker = LockoutTracker(threshold=2, duration_s=60)
        
        with patch('time.time') as mock_time:
            # Lock the user at time 1000
            mock_time.return_value = 1000.0
            tracker.record_failure("user1")
            tracker.record_failure("user1")  # Triggers lockout
            
            # Should be locked
            locked, remaining = tracker.is_locked("user1")
            assert locked == True
            
            # Move time forward to just before expiration
            mock_time.return_value = 1059.0
            locked, remaining = tracker.is_locked("user1")
            assert locked == True
            assert remaining == 1
            
            # Move time forward past expiration
            mock_time.return_value = 1061.0
            locked, remaining = tracker.is_locked("user1")
            assert locked == False
            assert remaining == 0
            # Lock should be removed from dict
            assert "user1" not in tracker.locked_until

    def test_record_success_clears_failures(self):
        """Test that recording success clears failures"""
        tracker = LockoutTracker(threshold=3, duration_s=60)
        
        # Record some failures
        tracker.record_failure("user1")
        tracker.record_failure("user1")
        assert tracker.failures["user1"] == 2
        
        # Record success
        tracker.record_success("user1")
        
        # Failures should be cleared
        assert "user1" not in tracker.failures

    def test_record_success_clears_lockout(self):
        """Test that recording success clears lockout"""
        tracker = LockoutTracker(threshold=2, duration_s=60)
        
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            # Trigger lockout
            tracker.record_failure("user1")
            tracker.record_failure("user1")
            
            # Should be locked
            locked, _ = tracker.is_locked("user1")
            assert locked == True
            
            # Record success
            tracker.record_success("user1")
            
            # Should no longer be locked
            locked, remaining = tracker.is_locked("user1")
            assert locked == False
            assert remaining == 0
            assert "user1" not in tracker.locked_until

    def test_multiple_keys_separate_tracking(self):
        """Test that different keys have separate failure tracking"""
        tracker = LockoutTracker(threshold=2, duration_s=60)
        
        # Record failures for user1
        tracker.record_failure("user1")
        tracker.record_failure("user1")  # user1 should be locked
        
        # Record failure for user2
        tracker.record_failure("user2")
        
        # user1 should be locked
        locked1, _ = tracker.is_locked("user1")
        assert locked1 == True
        
        # user2 should not be locked (only 1 failure)
        locked2, _ = tracker.is_locked("user2")
        assert locked2 == False
        assert tracker.failures["user2"] == 1

    def test_remaining_time_decreases_over_time(self):
        """Test that remaining lockout time decreases as time passes"""
        tracker = LockoutTracker(threshold=2, duration_s=100)
        
        with patch('time.time') as mock_time:
            # Lock at time 1000
            mock_time.return_value = 1000.0
            tracker.record_failure("user1")
            tracker.record_failure("user1")
            
            # Check at different times
            mock_time.return_value = 1010.0
            locked, remaining = tracker.is_locked("user1")
            assert locked == True
            assert remaining == 90
            
            mock_time.return_value = 1050.0
            locked, remaining = tracker.is_locked("user1")
            assert locked == True
            assert remaining == 50

    def test_failures_reset_after_lockout(self):
        """Test that failure count resets after lockout is triggered"""
        tracker = LockoutTracker(threshold=3, duration_s=60)
        
        # Trigger lockout
        tracker.record_failure("user1")
        tracker.record_failure("user1")
        tracker.record_failure("user1")
        
        # Failures should be reset to 0
        assert tracker.failures.get("user1", 0) == 0
        
        # After lockout expires, new failures start from 0
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            tracker.record_failure("user1")
            tracker.record_failure("user1")
            tracker.record_failure("user1")
            
            # Lockout should be set
            assert "user1" in tracker.locked_until
            
            # Expire the lockout
            mock_time.return_value = 1061.0
            tracker.is_locked("user1")  # This should clear the expired lockout
            
            # Record new failure - should start counting from 1
            tracker.record_failure("user1")
            assert tracker.failures["user1"] == 1

    def test_record_success_on_unlocked_key(self):
        """Test that recording success on an unlocked key doesn't cause errors"""
        tracker = LockoutTracker(threshold=3, duration_s=60)
        
        # Record success on a key that was never used
        tracker.record_success("user1")
        
        # Should not raise any errors
        locked, remaining = tracker.is_locked("user1")
        assert locked == False
        assert remaining == 0

    def test_lockout_at_exact_threshold(self):
        """Test that lockout triggers exactly at threshold"""
        tracker = LockoutTracker(threshold=5, duration_s=60)
        
        # Record failures up to threshold
        for i in range(4):
            tracker.record_failure("user1")
        
        # Should not be locked yet
        locked, _ = tracker.is_locked("user1")
        assert locked == False
        
        # 5th failure should trigger lockout
        tracker.record_failure("user1")
        locked, _ = tracker.is_locked("user1")
        assert locked == True

    def test_concurrent_failures_different_keys(self):
        """Test handling failures for multiple keys concurrently"""
        tracker = LockoutTracker(threshold=2, duration_s=60)
        
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0
            
            # Trigger lockout for user1
            tracker.record_failure("user1")
            tracker.record_failure("user1")
            
            # Record one failure for user2
            tracker.record_failure("user2")
            
            # user1 should be locked
            locked1, _ = tracker.is_locked("user1")
            assert locked1 == True
            
            # user2 should not be locked
            locked2, _ = tracker.is_locked("user2")
            assert locked2 == False
            
            # Complete lockout for user2
            tracker.record_failure("user2")
            locked2, _ = tracker.is_locked("user2")
            assert locked2 == True

    def test_lockout_cleanup_on_check(self):
        """Test that expired lockouts are cleaned up when checking"""
        tracker = LockoutTracker(threshold=2, duration_s=60)
        
        with patch('time.time') as mock_time:
            # Lock user1 at time 1000
            mock_time.return_value = 1000.0
            tracker.record_failure("user1")
            tracker.record_failure("user1")
            
            assert "user1" in tracker.locked_until
            
            # Move past expiration
            mock_time.return_value = 1061.0
            
            # Checking should clean up the expired lockout
            locked, _ = tracker.is_locked("user1")
            assert locked == False
            assert "user1" not in tracker.locked_until

    def test_zero_threshold_behavior(self):
        """Test behavior with zero threshold (should lock immediately)"""
        tracker = LockoutTracker(threshold=0, duration_s=60)
        
        # First failure should trigger lockout immediately
        tracker.record_failure("user1")
        locked, _ = tracker.is_locked("user1")
        assert locked == True

    def test_single_failure_threshold(self):
        """Test behavior with threshold of 1"""
        tracker = LockoutTracker(threshold=1, duration_s=60)
        
        # First failure should trigger lockout
        tracker.record_failure("user1")
        locked, _ = tracker.is_locked("user1")
        assert locked == True

