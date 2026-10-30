"""ThreatLens AI - Prediction Engine Tests."""

import pytest
from src.predict import load_models, predict_one


def test_predict_one_valid(sample_flow_dict):
    """Verify single-flow prediction produces expected output format and probability."""
    clf_art, reg_art = load_models()
    res = predict_one(
        row_dict=sample_flow_dict,
        clf_artifact=clf_art,
        reg_artifact=reg_art,
        store=False,
    )

    assert "predicted_label" in res
    assert res["predicted_label"] in [0, 1]
    assert 0.0 <= res["attack_probability"] <= 1.0
    assert res["predicted_total_bytes"] >= 0.0
    assert "prediction_id" not in res  # store=False


def test_predict_one_rejects_missing_field(sample_flow_dict):
    """Verify inference is rejected when mandatory feature columns are missing."""
    clf_art, reg_art = load_models()
    incomplete_dict = sample_flow_dict.copy()
    del incomplete_dict["duration"]

    with pytest.raises(ValueError, match="Missing required fields"):
        predict_one(
            row_dict=incomplete_dict,
            clf_artifact=clf_art,
            reg_artifact=reg_art,
            store=False,
        )


def test_predict_one_stores_in_db_when_enabled(sample_flow_dict, test_db):
    """Verify prediction is persisted to predictions collection when store=True."""
    from src.database import get_client, insert_prediction
    from src.config import PREDICTIONS_COLLECTION

    clf_art, reg_art = load_models()
    res = predict_one(
        row_dict=sample_flow_dict,
        clf_artifact=clf_art,
        reg_artifact=reg_art,
        store=True,
        source="test_verification",
    )

    assert "prediction_id" in res
    assert res["prediction_id"] is not None

