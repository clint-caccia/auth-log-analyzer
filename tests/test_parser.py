from analyzer.parser import parse_line

YEAR = 2026


def test_failed_password():
    e = parse_line("Nov 18 03:14:07 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 52344 ssh2", YEAR)
    assert e.event_type == "failed_password"
    assert e.user == "root"
    assert e.ip == "203.0.113.45"
    assert e.port == 52344
    assert e.timestamp.year == YEAR and e.timestamp.hour == 3


def test_failed_password_invalid_user():
    e = parse_line("Nov 18 09:40:00 web01 sshd[11]: Failed password for invalid user oracle from 198.51.100.23 port 40000 ssh2", YEAR)
    assert e.event_type == "failed_password"
    assert e.user == "oracle"


def test_invalid_user_line():
    e = parse_line("Nov 18 09:40:00 web01 sshd[11]: Invalid user oracle from 198.51.100.23 port 40000", YEAR)
    assert e.event_type == "invalid_user"
    assert e.user == "oracle"


def test_accepted_publickey():
    e = parse_line("Nov  3 10:01:00 web01 sshd[90]: Accepted publickey for clint from 10.0.0.12 port 51000 ssh2", YEAR)
    assert e.event_type == "accepted_login"
    assert e.method == "publickey"
    assert e.timestamp.day == 3


def test_sudo_command():
    e = parse_line("Nov 18 21:09:20 web01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", YEAR)
    assert e.event_type == "sudo_command"
    assert e.user == "deploy"
    assert e.target_user == "root"
    assert e.command == "/usr/bin/cat /etc/shadow"


def test_noise_is_skipped():
    assert parse_line("Nov 18 00:40:00 web01 CRON[2824]: pam_unix(cron:session): session opened for user root by (uid=0)", YEAR) is None
    assert parse_line("not a log line", YEAR) is None
    assert parse_line("", YEAR) is None
