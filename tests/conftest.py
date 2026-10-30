"""ThreatLens AI - Pytest Configuration and Global Fixtures."""

import pytest
import pandas as pd
from pymongo import MongoClient

from src.config import MONGO_TIMEOUT_MS, MONGO_URI
from src.database import MongoUnavailableError, ping

TEST_DB_NAME = "threatlens_test_db"


@pytest.fixture(scope="session")
def mongo_available() -> bool:
    """Check if MongoDB is reachable for test suite."""
    try:
        ping()
        return True
    except MongoUnavailableError:
        return False


@pytest.fixture(scope="function")
def test_db(mongo_available):
    """Provide a throwaway MongoDB database for testing, dropped on teardown."""
    if not mongo_available:
        pytest.skip("MongoDB service is unreachable at 127.0.0.1:27017.")

    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=MONGO_TIMEOUT_MS,
    )
    # Clean prior state if any before each test
    client.drop_database(TEST_DB_NAME)
    db = client[TEST_DB_NAME]

    yield db

    # Teardown: drop test database
    client.drop_database(TEST_DB_NAME)
    client.close()


@pytest.fixture
def sample_flow_dict():
    """Valid flow dictionary matching training features."""
    return {
        "duration": 1.5,
        "protocol": "tcp",
        "service": "http",
        "state": "established",
        "src_packets": 10,
        "dst_packets": 15,
        "dst_port": 80,
        "ttl": 64,
        "failed_logins": 0,
        "syn_flag_ratio": 0.02,
        "unique_dst_ports": 1,
        "conn_rate": 5.0,
        "src_bytes": 4000,
        "dst_bytes": 13500,
        "total_bytes": 17500,
        "label": 0,
        "attack_type": "normal",
        "split": "test",
        "source": "synthetic",
        "record_id": "TL-TEST01",
    }
