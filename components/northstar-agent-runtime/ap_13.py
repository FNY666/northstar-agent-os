"""title_case utility."""

def title_case(s):
    return ' '.join(w[:1].upper()+w[1:] for w in s.split())


def _self_test():
    assert title_case('hello world') == 'Hello World'
    assert title_case('') == ''


if __name__ == "__main__":
    _self_test()
    print("ap_13: OK")
