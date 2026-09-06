import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.risk_scoring import calculate_risk_score


def test_risk_scoring_low():
    score, level = calculate_risk_score(1)
    assert score == 10
    assert level == "LOW"

    score_zero, level_zero = calculate_risk_score(0)
    assert score_zero == 0
    assert level_zero == "LOW"


def test_risk_scoring_medium():
    score_3, level_3 = calculate_risk_score(3)
    assert score_3 == 40
    assert level_3 == "MEDIUM"

    score_4, level_4 = calculate_risk_score(4)
    assert score_4 == 40
    assert level_4 == "MEDIUM"


def test_risk_scoring_high():
    score_5, level_5 = calculate_risk_score(5)
    assert score_5 == 70
    assert level_5 == "HIGH"

    score_9, level_9 = calculate_risk_score(9)
    assert score_9 == 70
    assert level_9 == "HIGH"


def test_risk_scoring_critical():
    score_10, level_10 = calculate_risk_score(10)
    assert score_10 == 100
    assert level_10 == "CRITICAL"

    score_20, level_20 = calculate_risk_score(20)
    assert score_20 == 100
    assert level_20 == "CRITICAL"
