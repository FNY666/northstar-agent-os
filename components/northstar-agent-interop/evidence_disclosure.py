"""Self-contained inclusion disclosure: prove one event belongs to a root without shipping the bundle."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from evidence_bundle import EvidenceBundle, EvidenceError, _leaf, make_proof

SCHEMA = 'northstar.inclusion-disclosure.v1'
_DIRECTIONS = ('left', 'right')


class DisclosureError(EvidenceError):
    """Malformed, mismatched, or unverifiable inclusion disclosure."""


def _is_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith('sha256:')
        and all(character in '0123456789abcdef' for character in value[7:])
    )


@dataclass(frozen=True)
class DisclosureVerdict:
    state: str
    reasons: tuple = ()
    unverified: tuple = ()


@dataclass(frozen=True)
class Disclosure:
    schema_version: str
    root_digest: str
    leaf_count: int
    index: int
    siblings: tuple

    def to_dict(self):
        return {
            'schema_version': self.schema_version,
            'root_digest': self.root_digest,
            'leaf_count': self.leaf_count,
            'index': self.index,
            'siblings': [[direction, digest] for direction, digest in self.siblings],
        }

    @classmethod
    def from_dict(cls, value):
        fields = {'schema_version', 'root_digest', 'leaf_count', 'index', 'siblings'}
        if not isinstance(value, dict) or set(value) != fields:
            raise DisclosureError('disclosure fields are invalid')
        if value['schema_version'] != SCHEMA or not _is_digest(value['root_digest']):
            raise DisclosureError('disclosure header is invalid')
        count, index = value['leaf_count'], value['index']
        if not _is_int(count) or count < 1:
            raise DisclosureError('disclosure leaf count is invalid')
        if not _is_int(index) or not 0 <= index < count:
            raise DisclosureError('disclosure index is invalid')
        siblings = value['siblings']
        if not isinstance(siblings, (list, tuple)):
            raise DisclosureError('disclosure siblings are invalid')
        return cls(value['schema_version'], value['root_digest'], count, index,
                   tuple(_sibling(entry) for entry in siblings))

    def exposure(self):
        return {'root_digest': self.root_digest, 'leaf_count': self.leaf_count,
                'index': self.index, 'sibling_count': len(self.siblings),
                'reveals_other_leaves': False}


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _sibling(entry):
    if not isinstance(entry, (list, tuple)) or len(entry) != 2:
        raise DisclosureError('disclosure sibling is invalid')
    direction, digest = entry
    if direction not in _DIRECTIONS or not _is_digest(digest):
        raise DisclosureError('disclosure sibling is invalid')
    return (direction, digest)


def _depth(leaf_count):
    depth, size = 0, leaf_count
    while size > 1:
        size, depth = (size + 1) // 2, depth + 1
    return depth


def make_disclosure(bundle, index):
    if not isinstance(bundle, EvidenceBundle):
        raise DisclosureError('bundle is invalid')
    if not _is_int(index) or not 0 <= index < bundle.leaf_count:
        raise DisclosureError('disclosure index is invalid')
    return Disclosure(SCHEMA, bundle.root_digest, bundle.leaf_count, index,
                      tuple(make_proof(bundle, index).siblings))


def verify_disclosure(disclosure, *, subject, expected_root=None):
    if not isinstance(disclosure, Disclosure):
        raise DisclosureError('disclosure is invalid')
    if not isinstance(subject, dict):
        raise DisclosureError('subject must be an event object')
    if not _is_digest(disclosure.root_digest):
        raise DisclosureError('disclosure root is invalid')
    if not _is_int(disclosure.leaf_count) or disclosure.leaf_count < 1:
        raise DisclosureError('disclosure leaf count is invalid')
    if not _is_int(disclosure.index) or not 0 <= disclosure.index < disclosure.leaf_count:
        raise DisclosureError('disclosure index is invalid')
    if expected_root is not None:
        if not _is_digest(expected_root):
            raise DisclosureError('expected root is invalid')
        if expected_root != disclosure.root_digest:
            raise DisclosureError('disclosure root does not match the expected root')
    if len(disclosure.siblings) != _depth(disclosure.leaf_count):
        raise DisclosureError('disclosure path length does not match the leaf count')
    current = _leaf(subject)
    for direction, digest in disclosure.siblings:
        if direction not in _DIRECTIONS or not _is_digest(digest):
            raise DisclosureError('disclosure sibling is invalid')
        sibling = bytes.fromhex(digest[7:])
        current = hashlib.sha256(
            b'node\0' + (current + sibling if direction == 'right' else sibling + current)
        ).digest()
    if 'sha256:' + current.hex() != disclosure.root_digest:
        raise DisclosureError('disclosure root does not match the subject')
    bounds = ('index', 'leaf_count')
    if expected_root is None:
        return DisclosureVerdict('verified-unpinned', ('root_unpinned',), bounds)
    return DisclosureVerdict('verified', (), bounds)
