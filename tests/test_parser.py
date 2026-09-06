import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.parser import parse_log_line


def test_accepted_password_line():
    line = "Aug 14 10:00:01 server sshd[1001]: Accepted password for admin from 192.168.1.10 port 50120 ssh2"
    event = parse_log_line(line)
    assert event is not None
    assert event["status"] == "SUCCESS"
    assert event["username"] == "admin"
    assert event["ip"] == "192.168.1.10"
    assert event["port"] == 50120
    assert "Aug 14 10:00:01" in event["timestamp"]


def test_failed_password_line():
    line = "Aug 14 10:05:12 server sshd[1002]: Failed password for admin from 192.168.1.20 port 50121 ssh2"
    event = parse_log_line(line)
    assert event is not None
    assert event["status"] == "FAILED"
    assert event["username"] == "admin"
    assert event["ip"] == "192.168.1.20"
    assert event["port"] == 50121


def test_invalid_user_line():
    line = "Aug 14 10:05:18 server sshd[1003]: Failed password for invalid user admin from 192.168.1.20 port 50122 ssh2"
    event = parse_log_line(line)
    assert event is not None
    assert event["status"] == "FAILED"
    assert event["username"] == "admin"  # Must be 'admin', NOT 'invalid'
    assert event["ip"] == "192.168.1.20"


def test_invalid_log_line():
    line = "Aug 14 10:00:01 server systemd[1]: Started System Logging Service."
    event = parse_log_line(line)
    assert event is None
