"""
Unit tests for configuration module.
"""

import pytest
import os
from config import (
    # Paths
    PROJECT_ROOT, DATA_DIR, MODELS_DIR, PLOTS_DIR,
    # Data config
    TEST_SIZE, RANDOM_STATE,
    # Model configs
    RF_CONFIG, XGBOOST_CONFIG,
    # Thresholds
    DETECTION_THRESHOLD, ENSEMBLE_WEIGHT_RF, ENSEMBLE_WEIGHT_XGB,
    # Other configs
    CV_FOLDS, LOG_LEVEL
)


class TestConfigPaths:
    """Test that configuration paths are valid."""
    
    def test_project_root_exists(self):
        """Test that PROJECT_ROOT is defined and exists."""
        assert PROJECT_ROOT is not None
        assert os.path.exists(PROJECT_ROOT)
    
    def test_models_dir_exists(self):
        """Test that models directory was created."""
        assert os.path.exists(MODELS_DIR)
    
    def test_plots_dir_exists(self):
        """Test that plots directory was created."""
        assert os.path.exists(PLOTS_DIR)
    
    def test_data_dir_exists(self):
        """Test that data directory exists."""
        assert os.path.exists(DATA_DIR)


class TestDataConfig:
    """Test data preprocessing configuration."""
    
    def test_test_size_valid(self):
        """Test that test_size is a valid proportion."""
        assert 0 < TEST_SIZE < 1
        assert TEST_SIZE == 0.20  # 80/20 split
    
    def test_random_state_is_set(self):
        """Test that random state is set for reproducibility."""
        assert RANDOM_STATE is not None
        assert isinstance(RANDOM_STATE, int)
        assert RANDOM_STATE == 42


class TestModelConfigs:
    """Test model hyperparameter configurations."""
    
    def test_rf_config_is_dict(self):
        """Test that RF config is a dictionary."""
        assert isinstance(RF_CONFIG, dict)
        assert len(RF_CONFIG) > 0
    
    def test_rf_config_has_key_params(self):
        """Test that RF config has important parameters."""
        assert "n_estimators" in RF_CONFIG
        assert "max_depth" in RF_CONFIG
        assert "random_state" in RF_CONFIG
        assert RF_CONFIG["n_estimators"] > 0
    
    def test_xgboost_config_is_dict(self):
        """Test that XGBoost config is a dictionary."""
        assert isinstance(XGBOOST_CONFIG, dict)
        assert len(XGBOOST_CONFIG) > 0
    
    def test_xgboost_config_has_key_params(self):
        """Test that XGBoost config has important parameters."""
        assert "n_estimators" in XGBOOST_CONFIG
        assert "max_depth" in XGBOOST_CONFIG
        assert "learning_rate" in XGBOOST_CONFIG
        assert XGBOOST_CONFIG["n_estimators"] > 0


class TestDetectionThresholds:
    """Test detection and mitigation thresholds."""
    
    def test_detection_threshold_valid_range(self):
        """Test that detection threshold is in [0, 1]."""
        assert 0 <= DETECTION_THRESHOLD <= 1
        assert DETECTION_THRESHOLD == 0.60
    
    def test_ensemble_weights_sum_to_one(self):
        """Test that ensemble weights sum to 1."""
        weight_sum = ENSEMBLE_WEIGHT_RF + ENSEMBLE_WEIGHT_XGB
        assert abs(weight_sum - 1.0) < 0.001  # Allow small floating point error
    
    def test_ensemble_weights_in_valid_range(self):
        """Test that individual weights are in [0, 1]."""
        assert 0 <= ENSEMBLE_WEIGHT_RF <= 1
        assert 0 <= ENSEMBLE_WEIGHT_XGB <= 1


class TestOtherConfigs:
    """Test other configuration parameters."""
    
    def test_cv_folds_valid(self):
        """Test that cross-validation folds is reasonable."""
        assert CV_FOLDS >= 2
        assert CV_FOLDS <= 10
    
    def test_log_level_valid(self):
        """Test that log level is one of the valid options."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        assert LOG_LEVEL in valid_levels


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
