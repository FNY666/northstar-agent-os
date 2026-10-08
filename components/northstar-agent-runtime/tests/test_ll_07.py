"""Tests for ll_07 (palindrome check)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ll_07
from ll_07 import is_palindrome, from_list, to_list, LlError


def test_01_normal_case():
    assert is_palindrome(from_list([1, 2, 2, 1])) is True
    assert is_palindrome(from_list([1, 2, 3, 2, 1])) is True
    assert is_palindrome(from_list([1, 2, 3, 4])) is False


def test_02_edge_cases():
    assert is_palindrome(None) is True
    assert is_palindrome(from_list([5])) is True
    assert is_palindrome(from_list([1, 2])) is False
    assert is_palindrome(from_list([2, 2])) is True


def test_03_extra():
    head = from_list([1, 2, 3, 2, 1])
    assert is_palindrome(head) is True
    assert to_list(head) == [1, 2, 3, 2, 1]  # list must be restored
    head = from_list([1, 2, 3, 4])
    assert is_palindrome(head) is False
    assert to_list(head) == [1, 2, 3, 4]
    try:
        is_palindrome(object())
        raised = False
    except LlError:
        raised = True
    assert raised is True


def test_04_version_and_stdlib_only():
    assert ll_07.LL_07_VERSION == "ll-07.v1"
    assert ll_07.SCHEMA_PIN == "northstar.ll-07.v1"
    assert ll_07.stdlib_only() is True
