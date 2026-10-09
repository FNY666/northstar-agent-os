"""ax_40: now_iso utility (stdlib only)."""
def now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def run_tests():
    assert (now_iso().endswith('+00:00')) == True, "now_iso().endswith('+00:00')"
    assert ('T' in now_iso()) == True, "'T' in now_iso()"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_40: ok")
