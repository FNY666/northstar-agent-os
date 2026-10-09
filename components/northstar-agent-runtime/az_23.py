"""Camel to snake case. stdlib only."""

import re

def snake_case(s):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', s).lower()

def test():
    assert snake_case('camelCase') == 'camel_case'
    assert snake_case('a') == 'a'
    assert snake_case('HTML') == 'h_t_m_l'

if __name__ == '__main__':
    test(); print('ok')
