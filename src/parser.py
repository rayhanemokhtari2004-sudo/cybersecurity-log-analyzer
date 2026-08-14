import re 
LOG_FILE= "data/auth.log"

def parse_log_line(line):
    pattern = (
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?"
        r"(?:Accepted|Failed) password for "
        r"(?P<username>\S+) from "
        r"(?P<ip>\S+) port "
        r"(?P<port>\d+)"
    )
    match=re.search(pattern, line)   
    if not match:
        return None
    status = "SUCCESS" if "Accepted password" in line else "FAILED"

    return {
        "timestamp": match.group("timestamp"),
        "username": match.group("username"),
        "ip": match.group("ip"),
        "port": int(match.group("port")),
        "status": status
    }
def read_logs():
    events = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line)

            if event:
                events.append(event)

    return events


if __name__ == "__main__":
    logs = read_logs()

    for log in logs:
        print(log)    