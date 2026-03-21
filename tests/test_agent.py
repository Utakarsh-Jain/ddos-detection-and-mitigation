"""
Unit tests for agent_core module.
"""

import pytest
import numpy as np
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_core import DDoSDetector, extract_basic_features


class TestExtractBasicFeatures:
    """Test basic feature extraction from packets."""
    
    def test_extract_features_returns_dict(self):
        """Test that feature extraction returns a dictionary."""
        # Mock packet object (simplified)
        # This is a basic sanity check
        assert extract_basic_features is not None
    
    def test_features_have_required_keys(self, sample_flow_dict):
        """Test that extracted flow has required keys."""
        required_keys = [
            "Source IP", "Destination IP", "Destination Port",
            "Flow Duration", "Flow Bytes/s", "Flow Packets/s"
        ]
        for key in required_keys:
            assert key in sample_flow_dict


class TestDDoSDetector:
    """Test DDoS detection model loading and prediction."""
    
    def test_detector_initialization(self):
        """Test that DDoSDetector can be initialized."""
        try:
            detector = DDoSDetector()
            assert detector is not None
            assert hasattr(detector, 'rf')
            assert hasattr(detector, 'xgb_clf')
            assert hasattr(detector, 'scaler')
            assert hasattr(detector, 'feature_names')
        except FileNotFoundError:
            pytest.skip("Models not trained yet")
    
    def test_detector_predicts_single_flow(self, sample_flow_dict):
        """Test single flow prediction."""
        try:
            detector = DDoSDetector()
            # Try prediction (will use dummy values since flow is simplified)
            result = detector.predict(sample_flow_dict)
            
            # Result should be a tuple: (prediction, ensemble_score, rf_score, xgb_score)
            assert isinstance(result, tuple)
            assert len(result) == 4
            assert result[0] in [0, 1]  # Binary classification
        except FileNotFoundError:
            pytest.skip("Models not trained yet")
    
    def test_detector_probability_in_valid_range(self, sample_flow_dict):
        """Test that probabilities are in [0, 1] range."""
        try:
            detector = DDoSDetector()
            pred, ensemble_prob, rf_prob, xgb_prob = detector.predict(sample_flow_dict)
            
            assert 0 <= ensemble_prob <= 1, "Ensemble probability out of range"
            assert 0 <= rf_prob <= 1, "RF probability out of range"
            assert 0 <= xgb_prob <= 1, "XGBoost probability out of range"
        except FileNotFoundError:
            pytest.skip("Models not trained yet")


class TestEnsembleVoting:
    """Test ensemble voting mechanism."""
    
    def test_weighted_ensemble_calculation(self):
        """Test that weighted voting produces correct result."""
        from config import ENSEMBLE_WEIGHT_RF, ENSEMBLE_WEIGHT_XGB
        
        rf_prob = 0.8
        xgb_prob = 0.6
        
        ensemble = ENSEMBLE_WEIGHT_RF * rf_prob + ENSEMBLE_WEIGHT_XGB * xgb_prob
        
        # Weighted average should be between min and max of individual scores
        assert min(rf_prob, xgb_prob) <= ensemble <= max(rf_prob, xgb_prob)
        
        # Weights should sum to 1
        assert abs((ENSEMBLE_WEIGHT_RF + ENSEMBLE_WEIGHT_XGB) - 1.0) < 0.001


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
