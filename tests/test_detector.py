import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.detector import detect_brute_force


def test_brute_force_detected_within_5_mins():
    # 5 failed attempts within 5 minutes
    logs = [
        {"timestamp": "Aug 14 10:05:00", "username": "admin", "ip": "192.168.1.100", "port": 5001, "status": "FAILED"},
        {"timestamp": "Aug 14 10:05:30", "username": "admin", "ip": "192.168.1.100", "port": 5002, "status": "FAILED"},
        {"timestamp": "Aug 14 10:06:00", "username": "admin", "ip": "192.168.1.100", "port": 5003, "status": "FAILED"},
        {"timestamp": "Aug 14 10:07:00", "username": "admin", "ip": "192.168.1.100", "port": 5004, "status": "FAILED"},
        {"timestamp": "Aug 14 10:08:00", "username": "admin", "ip": "192.168.1.100", "port": 5005, "status": "FAILED"},
    ]
    alerts = detect_brute_force(logs)
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "192.168.1.100"
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["risk_score"] == 70
    assert alerts[0]["risk_level"] == "HIGH"


def test_brute_force_not_detected_under_threshold():
    # 4 failed attempts within 5 minutes (below threshold of 5)
    logs = [
        {"timestamp": "Aug 14 10:05:00", "username": "admin", "ip": "192.168.1.101", "port": 5001, "status": "FAILED"},
        {"timestamp": "Aug 14 10:05:30", "username": "admin", "ip": "192.168.1.101", "port": 5002, "status": "FAILED"},
        {"timestamp": "Aug 14 10:06:00", "username": "admin", "ip": "192.168.1.101", "port": 5003, "status": "FAILED"},
        {"timestamp": "Aug 14 10:07:00", "username": "admin", "ip": "192.168.1.101", "port": 5004, "status": "FAILED"},
    ]
    alerts = detect_brute_force(logs)
    assert len(alerts) == 0


def test_brute_force_spaced_out_attempts():
    # 5 failed attempts spaced over 30 minutes (more than 5 min window)
    logs = [
        {"timestamp": "Aug 14 10:00:00", "username": "admin", "ip": "192.168.1.102", "port": 5001, "status": "FAILED"},
        {"timestamp": "Aug 14 10:10:00", "username": "admin", "ip": "192.168.1.102", "port": 5002, "status": "FAILED"},
        {"timestamp": "Aug 14 10:20:00", "username": "admin", "ip": "192.168.1.102", "port": 5003, "status": "FAILED"},
        {"timestamp": "Aug 14 10:30:00", "username": "admin", "ip": "192.168.1.102", "port": 5004, "status": "FAILED"},
        {"timestamp": "Aug 14 10:40:00", "username": "admin", "ip": "192.168.1.102", "port": 5005, "status": "FAILED"},
    ]
    alerts = detect_brute_force(logs)
    assert len(alerts) == 0
