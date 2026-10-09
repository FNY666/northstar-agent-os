"""ak_25: Count vowels in text."""

def count_vowels(s):
    return sum(1 for c in s.lower() if c in 'aeiou')

if __name__ == '__main__':
    assert count_vowels('Hello World') == 3
    assert count_vowels('xyz') == 0
    print('ok')
