from datetime import datetime, timezone, timedelta
from pulseops.collectors.ssl_checker import parse_ssl_expiry_date

def test_parse_ssl_expiry_date():
    # Example format from standard ssl.getpeercert(): "Oct 28 12:00:00 2026 GMT"
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=45)
    # Format according to SSL spec: "%b %d %H:%M:%S %Y %Z"
    date_str = future.strftime("%b %d %H:%M:%S %Y GMT")
    
    days_left = parse_ssl_expiry_date(date_str)
    assert days_left is not None
    assert 44 <= days_left <= 46

def test_parse_invalid_ssl_date():
    assert parse_ssl_expiry_date("invalid date string") is None
    assert parse_ssl_expiry_date("") is None
