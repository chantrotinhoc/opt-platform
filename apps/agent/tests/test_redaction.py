from opt_agent.redaction import Redactor

SAMPLE = ("Host db01.corp.local (10.0.5.12) leaks password=Sup3r!Secret "
          "and admin@example.vn; 10.0.5.12 also runs SSH.")


def test_redaction_removes_sensitive_values():
    r = Redactor()
    out = r.redact(SAMPLE)
    for secret in ["10.0.5.12", "Sup3r!Secret", "admin@example.vn", "db01.corp.local"]:
        assert secret not in out


def test_same_value_gets_same_token_and_round_trips():
    r = Redactor()
    out = r.redact(SAMPLE)
    assert out.count("<IP_1_") == 2
    assert r.restore(out) == SAMPLE


def test_ipv6_redacted():
    r = Redactor()
    text = "SSH on fe80::1ff:fe23:4567:890a and 2001:db8::8a2e:370:7334"
    out = r.redact(text)
    assert "fe80" not in out and "2001:db8" not in out
    assert r.restore(out) == text


def test_quoted_and_spaced_credentials_redacted():
    r = Redactor()
    text = 'password="S3cr3t value" token = abc123 api_key: \'k-999\''
    out = r.redact(text)
    for secret in ["S3cr3t value", "abc123", "k-999"]:
        assert secret not in out
    assert r.restore(out) == text


def test_literal_placeholder_like_text_survives_round_trip():
    r = Redactor()
    text = "IP_1 10.0.0.1 SECRET_1"
    assert r.restore(r.redact(text)) == text
