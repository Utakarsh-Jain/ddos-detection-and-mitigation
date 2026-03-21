"""
Unit tests configuration and shared fixtures.
"""

import pytest
import numpy as np
import pandas as pd
import tempfile
import os
from pathlib import Path


@pytest.fixture
def sample_traffic_data():
    """Create sample network traffic data for testing."""
    np.random.seed(42)
    n_samples = 100
    n_features = 38
    
    # Create realistic flow data
    X = np.random.randn(n_samples, n_features)
    y = np.random.randint(0, 2, n_samples)
    
    feature_names = [f"Feature_{i}" for i in range(n_features)]
    
    return X, y, feature_names


@pytest.fixture
def sample_flow_dict():
    """Create a sample flow dictionary."""
    return {
        "Source IP": "192.168.1.100",
        "Destination IP": "10.0.0.1",
        "Destination Port": 443,
        "Flow Duration": 1000000,
        "Flow Bytes/s": 1024.5,
        "Flow Packets/s": 10.2,
        "Total Fwd Packets": 50,
        "Total Backward Packets": 50,
        "SYN Flag Count": 1,
        "ACK Flag Count": 50,
        "FIN Flag Count": 1,
        "RST Flag Count": 0,
        "Average Packet Size": 512.0,
    }


@pytest.fixture
def temp_model_dir():
    """Create a temporary directory for model files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir
