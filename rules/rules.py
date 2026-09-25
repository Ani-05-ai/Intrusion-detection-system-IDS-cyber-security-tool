def check_invalid_user_ssh(event):
    if event.get("event_type") == "invalid_user_ssh":
        return {
            "rule": "invalid_user_ssh",
            "detected": True,
            "severity": "high",
            "reason": "SSH login attempt using an invalid or unauthorized username"
        }

    return None


def check_command_injection(event):
    payload = str(event.get("url", "")).lower()

    suspicious_patterns = [
        ";",
        "&&",
        "||",
        "|",
        "`",
        "$(",
        "wget ",
        "curl ",
        "cat /etc/passwd"
    ]

    for pattern in suspicious_patterns:
        if pattern in payload:
            return {
                "rule": "command_injection",
                "detected": True,
                "severity": "high",
                "reason": f"Possible command injection pattern detected: {pattern}"
            }

    return None


def check_xss(event):
    payload = str(event.get("url", "")).lower()

    suspicious_patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "<img"
    ]

    for pattern in suspicious_patterns:
        if pattern in payload:
            return {
                "rule": "xss_attempt",
                "detected": True,
                "severity": "high",
                "reason": f"Possible XSS pattern detected: {pattern}"
            }

    return None


def check_path_traversal(event):
    payload = str(event.get("url", "")).lower()

    suspicious_patterns = [
        "../",
        "..\\",
        "%2e%2e",
        "%252e%252e"
    ]

    for pattern in suspicious_patterns:
        if pattern in payload:
            return {
                "rule": "path_traversal",
                "detected": True,
                "severity": "high",
                "reason": f"Possible path traversal pattern detected: {pattern}"
            }

    return None


def check_suspicious_http_method(event):
    method = str(event.get("method", "")).upper()

    suspicious_methods = [
        "TRACE",
        "CONNECT",
        "TRACK"
    ]

    if method in suspicious_methods:
        return {
            "rule": "suspicious_http_method",
            "detected": True,
            "severity": "medium",
            "reason": f"Suspicious HTTP method detected: {method}"
        }

    return None


def check_admin_probe(event):
    url = str(event.get("url", "")).lower()

    admin_paths = [
        "/admin",
        "/administrator",
        "/admin/login",
        "/wp-admin",
        "/phpmyadmin"
    ]

    for path in admin_paths:
        if path in url:
            return {
                "rule": "admin_probe",
                "detected": True,
                "severity": "medium",
                "reason": f"Request probing administrative endpoint: {path}"
            }

    return None


def check_sensitive_file_probe(event):
    url = str(event.get("url", "")).lower()

    sensitive_paths = [
        ".env",
        "/etc/passwd",
        "config.php",
        "web.config",
        ".git/",
        "id_rsa"
    ]

    for path in sensitive_paths:
        if path in url:
            return {
                "rule": "sensitive_file_probe",
                "detected": True,
                "severity": "high",
                "reason": f"Attempt to access sensitive resource: {path}"
            }

    return None

def run_rules(event):
    results = []

    rules = [
        check_invalid_user_ssh,
        check_command_injection,
        check_xss,
        check_path_traversal,
        check_suspicious_http_method,
        check_admin_probe,
        check_sensitive_file_probe,
        check_brute_force
    ]

    for rule in rules:
        result = rule(event)

        if result is not None:
            results.append(result)

    return results

from collections import defaultdict

failed_login_tracker = defaultdict(list)

def check_brute_force(event):#for tetsing
    if event.get("event_type") != "failed_ssh_login":
        return None

    source_ip = event.get("source_ip")

    failed_login_tracker[source_ip].append(event)

    if len(failed_login_tracker[source_ip]) >= 5:
        return {
            "rule": "brute_force",
            "detected": True,
            "severity": "high",
            "reason": "Multiple failed SSH login attempts detected"
        }

    return None
