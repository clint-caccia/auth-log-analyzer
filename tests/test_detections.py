from datetime import datetime, timedelta

from analyzer.detections import (
    detect_brute_force,
    detect_password_spray,
    detect_root_attempts,
    detect_sensitive_sudo,
    detect_success_after_failures,
)
from analyzer.parser import AuthEvent

T0 = datetime(2026, 11, 18, 12, 0, 0)


def fail(minutes, user="root", ip="203.0.113.1"):
    return AuthEvent(timestamp=T0 + timedelta(minutes=minutes), host="h", process="sshd",
                     event_type="failed_password", user=user, ip=ip)


def ok(minutes, user="deploy", ip="203.0.113.1", method="password"):
    return AuthEvent(timestamp=T0 + timedelta(minutes=minutes), host="h", process="sshd",
                     event_type="accepted_login", user=user, ip=ip, method=method)


def sudo(command, user="deploy"):
    return AuthEvent(timestamp=T0, host="h", process="sudo", event_type="sudo_command",
                     user=user, target_user="root", command=command)


def test_brute_force_triggers_at_threshold():
    events = [fail(m) for m in range(5)]
    found = detect_brute_force(events, threshold=5, window_minutes=10)
    assert len(found) == 1
    assert found[0].count == 5


def test_brute_force_ignores_slow_attempts():
    # 5 failures, but 20 minutes apart, so never 5 inside one 10 minute window
    events = [fail(m * 20) for m in range(5)]
    assert detect_brute_force(events, threshold=5, window_minutes=10) == []


def test_brute_force_counts_each_ip_separately():
    events = [fail(m, ip="203.0.113.1") for m in range(3)] + [fail(m, ip="203.0.113.2") for m in range(3)]
    assert detect_brute_force(events, threshold=5, window_minutes=10) == []


def test_password_spray():
    users = ["admin", "test", "oracle", "pi", "git"]
    events = [fail(i, user=u, ip="198.51.100.23") for i, u in enumerate(users)]
    found = detect_password_spray(events, min_users=5)
    assert len(found) == 1
    assert found[0].users == sorted(users)


def test_success_after_failures():
    events = [fail(m, user="deploy") for m in range(4)] + [ok(5)]
    found = detect_success_after_failures(events, min_failures=3)
    assert len(found) == 1
    assert found[0].severity == "high"


def test_success_without_failures_is_fine():
    assert detect_success_after_failures([ok(1)]) == []


def test_root_success_is_high():
    events = [fail(1), ok(2, user="root")]
    found = detect_root_attempts(events)
    assert found[0].severity == "high"


def test_sensitive_sudo():
    assert len(detect_sensitive_sudo([sudo("/usr/bin/cat /etc/shadow")])) == 1
    assert len(detect_sensitive_sudo([sudo("/usr/sbin/useradd -m backdoor")])) == 1


def test_routine_sudo_is_not_flagged():
    routine = [sudo("/usr/bin/apt update"), sudo("/usr/bin/rsync -a /src /dst"), sudo("/usr/bin/systemctl restart nginx")]
    assert detect_sensitive_sudo(routine) == []
