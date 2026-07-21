import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


# ANSI colors for terminal output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


# Match IPv4 addresses
IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

# Match the beginning of Linux log timestamps
TIME_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

# Patterns used to detect failed login attempts
FAILED_PATTERNS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "login failed",
)

# Patterns used to detect successful login attempts
SUCCESS_PATTERNS = (
    "accepted password",
    "accepted publickey",
    "login successful",
)


def is_valid_ipv4(ip_address):
    # Split the IP address into four parts
    parts = ip_address.split(".")

    if len(parts) != 4:
        return False

    # Check that every part is between 0 and 255
    for part in parts:
        if not part.isdigit():
            return False

        if not 0 <= int(part) <= 255:
            return False

    return True


def extract_ip(log_line):
    # Find all possible IP addresses in the log line
    matches = IP_PATTERN.findall(log_line)

    for ip_address in matches:
        if is_valid_ipv4(ip_address):
            return ip_address

    return None


def extract_time(log_line):
    # Extract the timestamp from the beginning of the line
    match = TIME_PATTERN.search(log_line)

    if not match:
        return None

    timestamp_text = match.group(1)

    try:
        # Add the current year because Linux logs usually omit it
        current_year = datetime.now().year
        return datetime.strptime(
            f"{current_year} {timestamp_text}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def get_login_status(log_line):
    # Convert the line to lowercase for easier matching
    lowercase_line = log_line.lower()

    for pattern in FAILED_PATTERNS:
        if pattern in lowercase_line:
            return "failed"

    for pattern in SUCCESS_PATTERNS:
        if pattern in lowercase_line:
            return "successful"

    return None


def extract_username(log_line):
    # Match failed login lines with an invalid user
    invalid_user_match = re.search(
        r"invalid user\s+([^\s]+)",
        log_line,
        re.IGNORECASE,
    )

    if invalid_user_match:
        return invalid_user_match.group(1)

    # Match common SSH login formats
    user_match = re.search(
        r"(?:for|user)\s+([^\s]+)\s+from",
        log_line,
        re.IGNORECASE,
    )

    if user_match:
        username = user_match.group(1)

        if username.lower() != "invalid":
            return username

    return "unknown"


def analyze_log(filename):
    # Store failed attempts by IP address
    failed_by_ip = Counter()

    # Store successful attempts by IP address
    successful_by_ip = Counter()

    # Store attacked usernames
    attacked_users = Counter()

    # Store failed attempt times for brute force detection
    failed_times = defaultdict(list)

    total_lines = 0
    failed_logins = 0
    successful_logins = 0

    with open(
        filename,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as log_file:

        for line in log_file:
            total_lines += 1

            status = get_login_status(line)

            if status is None:
                continue

            ip_address = extract_ip(line)
            timestamp = extract_time(line)
            username = extract_username(line)

            if status == "failed":
                failed_logins += 1
                attacked_users[username] += 1

                if ip_address:
                    failed_by_ip[ip_address] += 1

                    if timestamp:
                        failed_times[ip_address].append(timestamp)

            elif status == "successful":
                successful_logins += 1

                if ip_address:
                    successful_by_ip[ip_address] += 1

    return {
        "total_lines": total_lines,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "failed_by_ip": failed_by_ip,
        "successful_by_ip": successful_by_ip,
        "attacked_users": attacked_users,
        "failed_times": failed_times,
    }


def detect_brute_force(attempt_times, threshold, time_window):
    # Return False when there are not enough attempts
    if len(attempt_times) < threshold:
        return False

    # Sort attempts from oldest to newest
    sorted_times = sorted(attempt_times)

    # Use a moving time window to detect rapid attempts
    start_index = 0

    for end_index in range(len(sorted_times)):
        while (
            sorted_times[end_index] - sorted_times[start_index]
        ).total_seconds() > time_window:
            start_index += 1

        attempts_in_window = end_index - start_index + 1

        if attempts_in_window >= threshold:
            return True

    return False


def format_time(timestamp):
    # Format timestamps for readable output
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def print_ip_report(data, threshold, time_window):
    failed_by_ip = data["failed_by_ip"]
    successful_by_ip = data["successful_by_ip"]
    failed_times = data["failed_times"]

    print(f"\n{CYAN}IP address report{RESET}")
    print("-" * 75)

    all_ips = set(failed_by_ip) | set(successful_by_ip)

    if not all_ips:
        print("No login attempts with valid IP addresses were found")
        return

    for ip_address in sorted(
        all_ips,
        key=lambda current_ip: failed_by_ip[current_ip],
        reverse=True,
    ):
        failed_count = failed_by_ip[ip_address]
        success_count = successful_by_ip[ip_address]
        attempt_times = failed_times[ip_address]

        brute_force = detect_brute_force(
            attempt_times,
            threshold,
            time_window,
        )

        if brute_force:
            status_text = f"{RED}BRUTE FORCE{RESET}"
        elif failed_count >= threshold:
            status_text = f"{YELLOW}SUSPICIOUS{RESET}"
        else:
            status_text = f"{GREEN}NORMAL{RESET}"

        print(f"\nIP address: {ip_address}")
        print(f"Failed logins: {failed_count}")
        print(f"Successful logins: {success_count}")
        print(f"Status: {status_text}")

        if attempt_times:
            first_attempt = min(attempt_times)
            last_attempt = max(attempt_times)

            print(
                f"First failed attempt: "
                f"{format_time(first_attempt)}"
            )
            print(
                f"Last failed attempt: "
                f"{format_time(last_attempt)}"
            )


def print_user_report(attacked_users):
    print(f"\n{CYAN}Targeted users{RESET}")
    print("-" * 40)

    if not attacked_users:
        print("No targeted usernames were found")
        return

    for username, attempts in attacked_users.most_common():
        print(
            f"{username:<20} "
            f"Failed attempts: {attempts}"
        )


def print_summary(data):
    print(f"\n{CYAN}Login log summary{RESET}")
    print("-" * 40)

    print(f"Total log lines: {data['total_lines']}")

    print(
        f"{RED}Failed login attempts: "
        f"{data['failed_logins']}{RESET}"
    )

    print(
        f"{GREEN}Successful login attempts: "
        f"{data['successful_logins']}{RESET}"
    )

    print(
        f"Unique failed IP addresses: "
        f"{len(data['failed_by_ip'])}"
    )


def main():
    # Create the command line argument parser
    parser = argparse.ArgumentParser(
        description="Analyze login attempts in a log file"
    )

    parser.add_argument(
        "file",
        help="Path to the log file",
    )

    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required for brute force detection",
    )

    parser.add_argument(
        "-w",
        "--window",
        type=int,
        default=60,
        help="Brute force time window in seconds",
    )

    args = parser.parse_args()
    log_path = Path(args.file)

    # Check that the selected log file exists
    if not log_path.is_file():
        parser.error(
            f"Log file does not exist: {log_path}"
        )

    # Prevent invalid threshold values
    if args.threshold <= 0:
        parser.error(
            "Threshold must be greater than zero"
        )

    # Prevent invalid time window values
    if args.window <= 0:
        parser.error(
            "Time window must be greater than zero"
        )

    data = analyze_log(log_path)

    print_summary(data)

    print_ip_report(
        data,
        args.threshold,
        args.window,
    )

    print_user_report(
        data["attacked_users"]
    )


if __name__ == "__main__":
    main()