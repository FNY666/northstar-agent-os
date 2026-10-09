"""ax_44: running_total utility (stdlib only)."""
def running_total(nums):
    t, out = 0, []
    for n in nums: t += n; out.append(t)
    return out


def run_tests():
    assert (running_total([1,2,3])) == [1, 3, 6], 'running_total([1,2,3])'
    assert (running_total([])) == [], 'running_total([])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_44: ok")
