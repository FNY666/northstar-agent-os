"""Internationalization manager: message catalogs + CLDR plural rules.

Research note: a runtime that talks to humans needs localized text. ICU
MessageFormat is the industry standard for parameterized messages
(``{name}``, ``{n, plural, one {...} other {...}}``,
``{g, select, male {...} other {...}}``), and CLDR defines the plural
*category* rules per locale (English ``one/other``; Russian ``one/few/many``;
Arabic ``zero/one/two/few/many/other``; Chinese/Japanese ``other`` only).
Getting this wrong means shipping strings like "1 items" or picking the
wrong Slavic noun form — a correctness surface, not cosmetics.

The load-bearing invariants of this module are:

* **Deterministic message resolution** — a key resolves through an explicit
  locale fallback chain (``pt-BR`` -> ``pt`` -> ``default``); nothing is
  ever silently swallowed: a key missing everywhere raises
  :class:`MissingMessageError` fail-closed.
* **CLDR-shaped plural rules** — a pinned rule table per locale base
  (en/fr/de/es/ru/pl/ar/zh/ja/ko/cs/sk/...); explicit ``=N`` matches beat
  categories; ``#`` substitutes the count inside plural bodies.
* **Exact-count typing** — counts are ints; bools/floats/negatives are
  refused fail-closed (a count of ``1.5`` is a formatting bug, not a
  plural category).
* **BCP 47 tag discipline** — tags are normalized (``en-US`` ->
  ``en-us``-canonical ``en-US``); malformed tags are refused at the
  boundary.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (no wall-clock, no RNG), RLock-guarded, fail-closed
(:class:`I18nError` taxonomy), stdlib-only, digest-pinned records,
audit events shaped for ``audit.ndjson/1`` (ids + digest pins only —
never message content), ``main()`` self-check.

Honest scope: this is a *message bookkeeping* interface, not a
translation service. It pins what the host *loaded*; it cannot verify a
translation's quality, prove a catalog is complete, or detect a locale
mismatch the host caused (GIGO, same boundary as every other
bookkeeping module). Plural rules cover a representative CLDR subset —
real deployments needing all 200+ locales should pin the CLDR version
they ship.

Version pin: i18n-manager.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Mapping, Optional, Tuple

VERSION = "i18n-manager.v1"
SCHEMA = "northstar.i18n-manager.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "I18nError",
    "InvalidTagError",
    "UnknownLocaleError",
    "DuplicateLocaleError",
    "InvalidCatalogError",
    "MissingMessageError",
    "MessageFormatError",
    "InvalidCountError",
    "SequenceError",
    "LocaleRecord",
    "CatalogRecord",
    "PluralCategory",
    "I18nManager",
    "PLURAL_LOCALES",
    "i18n_manager_audit_event",
]


class I18nError(Exception):
    """Base for all i18n-manager errors (fail-closed taxonomy)."""


class InvalidTagError(I18nError):
    """Malformed BCP 47 language tag."""


class UnknownLocaleError(I18nError):
    """Locale not registered with this manager."""


class DuplicateLocaleError(I18nError):
    """Locale already registered."""


class InvalidCatalogError(I18nError):
    """Bad message catalog (non-mapping, bad keys/messages)."""


class MissingMessageError(I18nError):
    """Key missing in locale and every fallback."""


class MessageFormatError(I18nError):
    """Unparseable ICU message pattern or bad arguments."""


class InvalidCountError(I18nError):
    """Bad plural count (bool/float/negative/non-int)."""


class SequenceError(I18nError):
    """Non-increasing caller seq."""


_TAG_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")
_MAX_NEST = 8


def _normalize_tag(tag: str) -> str:
    """Canonicalize a BCP 47 tag: lower-region, keep case elsewhere-ish."""
    if not isinstance(tag, str) or not _TAG_RE.match(tag):
        raise InvalidTagError(f"malformed tag: {tag!r}")
    parts = tag.split("-")
    parts[0] = parts[0].lower()
    if len(parts) > 1 and len(parts[1]) == 2 and parts[1].isalpha():
        parts[1] = parts[1].upper()
    return "-".join(parts)


def _tag_bases(tag: str):
    """Yield tag, then progressively shorter bases (pt-BR -> pt)."""
    yield tag
    parts = tag.split("-")
    for i in range(len(parts) - 1, 0, -1):
        yield "-".join(parts[:i])


def _digest(tag: str, payload: str) -> str:
    return "sha256:" + hashlib.sha256(f"{tag}\x00{payload}".encode()).hexdigest()


# ---------------------------------------------------------------------------
# CLDR plural rules (representative subset). Each rule maps |n| -> category.
# ---------------------------------------------------------------------------

def _rule_en(n: int) -> str:
    return "one" if n == 1 else "other"


def _rule_fr(n: int) -> str:
    # French: 0 and 1 are singular (CLDR "one" includes 0, 1).
    return "one" if n in (0, 1) else "other"


def _rule_ru(n: int) -> str:
    mod10, mod100 = n % 10, n % 100
    if mod10 == 1 and mod100 != 11:
        return "one"
    if 2 <= mod10 <= 4 and not 12 <= mod100 <= 14:
        return "few"
    if mod10 == 0 or 5 <= mod10 <= 9 or 11 <= mod100 <= 14:
        return "many"
    return "other"


def _rule_pl(n: int) -> str:
    mod10, mod100 = n % 10, n % 100
    if n == 1:
        return "one"
    if 2 <= mod10 <= 4 and not 12 <= mod100 <= 14:
        return "few"
    if mod10 in (0, 1) or 5 <= mod10 <= 9 or 12 <= mod100 <= 14:
        return "many"
    return "other"


def _rule_ar(n: int) -> str:
    if n == 0:
        return "zero"
    if n == 1:
        return "one"
    if n == 2:
        return "two"
    mod100 = n % 100
    if 3 <= mod100 <= 10:
        return "few"
    if 11 <= mod100 <= 99:
        return "many"
    return "other"


def _rule_other_only(_n: int) -> str:
    return "other"


def _rule_cs(n: int) -> str:
    if n == 1:
        return "one"
    if 2 <= n <= 4:
        return "few"
    return "other"


def _rule_ga(n: int) -> str:
    if n == 1:
        return "one"
    if n == 2:
        return "two"
    if 3 <= n <= 6:
        return "few"
    if 7 <= n <= 10:
        return "many"
    return "other"


#: locale base -> (rule function, categories in canonical order)
PLURAL_RULES: Dict[str, Tuple] = {
    "en": (_rule_en, ("one", "other")),
    "de": (_rule_en, ("one", "other")),
    "es": (_rule_en, ("one", "other")),
    "it": (_rule_en, ("one", "other")),
    "nl": (_rule_en, ("one", "other")),
    "sv": (_rule_en, ("one", "other")),
    "da": (_rule_en, ("one", "other")),
    "fi": (_rule_en, ("one", "other")),
    "el": (_rule_en, ("one", "other")),
    "hu": (_rule_en, ("one", "other")),
    "tr": (_rule_en, ("one", "other")),
    "pt": (_rule_en, ("one", "other")),
    "fr": (_rule_fr, ("one", "other")),
    "ru": (_rule_ru, ("one", "few", "many", "other")),
    "uk": (_rule_ru, ("one", "few", "many", "other")),
    "be": (_rule_ru, ("one", "few", "many", "other")),
    "hr": (_rule_ru, ("one", "few", "many", "other")),
    "sr": (_rule_ru, ("one", "few", "many", "other")),
    "bs": (_rule_ru, ("one", "few", "many", "other")),
    "pl": (_rule_pl, ("one", "few", "many", "other")),
    "ar": (_rule_ar, ("zero", "one", "two", "few", "many", "other")),
    "zh": (_rule_other_only, ("other",)),
    "ja": (_rule_other_only, ("other",)),
    "ko": (_rule_other_only, ("other",)),
    "th": (_rule_other_only, ("other",)),
    "vi": (_rule_other_only, ("other",)),
    "cs": (_rule_cs, ("one", "few", "other")),
    "sk": (_rule_cs, ("one", "few", "other")),
    "ga": (_rule_ga, ("one", "two", "few", "many", "other")),
}

PLURAL_LOCALES: FrozenSet[str] = frozenset(PLURAL_RULES)


def _check_count(n) -> int:
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise InvalidCountError(f"count must be a non-negative int, got {n!r}")
    return n


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LocaleRecord:
    tag: str
    display_name: str
    seq: int
    digest: str

    def as_dict(self):
        return {"tag": self.tag, "display_name": self.display_name,
                "seq": self.seq, "digest": self.digest}


@dataclass(frozen=True)
class CatalogRecord:
    tag: str
    key_count: int
    seq: int
    digest: str

    def as_dict(self):
        return {"tag": self.tag, "key_count": self.key_count,
                "seq": self.seq, "digest": self.digest}


@dataclass(frozen=True)
class PluralCategory:
    locale: str
    count: int
    category: str
    seq: int

    def as_dict(self):
        return {"locale": self.locale, "count": self.count,
                "category": self.category, "seq": self.seq}


# ---------------------------------------------------------------------------
# ICU MessageFormat (small deterministic subset)
# ---------------------------------------------------------------------------

def _format_message(pattern: str, args: Mapping[str, object],
                    count_hint: Optional[int] = None) -> str:
    return _parse_nodes(pattern, args, 0)[0]


def _parse_nodes(pattern: str, args: Mapping[str, object],
                 depth: int) -> Tuple[str, int]:
    """Parse ``pattern``; returns (rendered, chars consumed)."""
    if depth > _MAX_NEST:
        raise MessageFormatError("message nesting too deep")
    out = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "{":
            rendered, i = _parse_argument(pattern, i, args, depth)
            out.append(rendered)
        elif ch == "}":
            raise MessageFormatError("unbalanced '}' in message")
        elif ch == "'" :
            # ICU apostrophe quoting: '' -> ', '{...}'-quoted text handled below
            if i + 1 < n and pattern[i + 1] == "'":
                out.append("'")
                i += 2
            else:
                j = pattern.find("'", i + 1)
                if j == -1:
                    raise MessageFormatError("unterminated quoted text")
                out.append(pattern[i + 1:j])
                i = j + 1
        elif ch == "#" and isinstance(args, dict) and "\x00count" in args:
            out.append(str(args["\x00count"]))
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out), n


def _parse_argument(pattern: str, i: int, args: Mapping[str, object],
                    depth: int) -> Tuple[str, int]:
    """Parse one {...} argument starting at ``i``; returns (rendered, next_i)."""
    assert pattern[i] == "{"
    j = _find_matching(pattern, i)
    inner = pattern[i + 1:j]
    parts = _split_top(inner, ",")
    name = parts[0].strip()
    if not name:
        raise MessageFormatError("empty argument name")
    if len(parts) == 1:
        if name not in args:
            raise MessageFormatError(f"missing argument: {name!r}")
        return str(args[name]), j + 1
    kind = parts[1].strip()
    body = ",".join(parts[2:]) if len(parts) > 2 else ""
    if kind == "plural":
        if name not in args:
            raise MessageFormatError(f"missing count argument: {name!r}")
        count = _check_count(args[name])
        return _render_plural(body, count, args, depth), j + 1
    if kind == "select":
        if name not in args:
            raise MessageFormatError(f"missing select argument: {name!r}")
        key = str(args[name])
        return _render_select(body, key, args, depth), j + 1
    if kind == "number":
        if name not in args:
            raise MessageFormatError(f"missing number argument: {name!r}")
        return _render_number(args[name]), j + 1
    raise MessageFormatError(f"unknown argument type: {kind!r}")


def _find_matching(pattern: str, i: int) -> int:
    depth = 0
    j = i
    in_quote = False
    while j < len(pattern):
        ch = pattern[j]
        if in_quote:
            if ch == "'":
                in_quote = False
            j += 1
            continue
        if ch == "'":
            in_quote = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    raise MessageFormatError("unbalanced '{' in message")


def _split_top(text: str, sep: str):
    parts, depth, cur = [], 0, []
    in_quote = False
    for ch in text:
        if in_quote:
            cur.append(ch)
            if ch == "'":
                in_quote = False
            continue
        if ch == "'":
            in_quote = True
            cur.append(ch)
        elif ch == "{":
            depth += 1
            cur.append(ch)
        elif ch == "}":
            depth -= 1
            cur.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _split_options(body: str):
    """Split ``key {msg} key {msg}`` into (key, msg) pairs."""
    opts = []
    i, n = 0, len(body)
    while i < n:
        while i < n and body[i].isspace():
            i += 1
        if i >= n:
            break
        m = re.match(r"(=\d+|\w+)", body[i:])
        if not m:
            raise MessageFormatError(f"bad plural/select option near {body[i:]!r}")
        key = m.group(1)
        i += len(key)
        while i < n and body[i].isspace():
            i += 1
        if i >= n or body[i] != "{":
            raise MessageFormatError("option missing '{...}' body")
        j = _find_matching(body, i)
        opts.append((key, body[i + 1:j]))
        i = j + 1
    if not opts:
        raise MessageFormatError("plural/select needs at least one option")
    return opts


def _render_plural(body: str, count: int, args: Mapping, depth: int) -> str:
    opts = dict(_split_options(body))
    if f"={count}" in opts:
        chosen = opts[f"={count}"]
    else:
        # category is chosen by the active locale's rule — caller passes rule
        rule = args.get("\x00rule")
        cat = rule(count) if rule else "other"
        chosen = opts.get(cat, opts.get("other"))
        if chosen is None:
            raise MessageFormatError(
                f"no plural option for category {cat!r} and no 'other'")
    sub_args = dict(args)
    sub_args["\x00count"] = count
    return _parse_nodes(chosen, sub_args, depth + 1)[0]


def _render_select(body: str, key: str, args: Mapping, depth: int) -> str:
    opts = dict(_split_options(body))
    chosen = opts.get(key, opts.get("other"))
    if chosen is None:
        raise MessageFormatError(f"no select option for {key!r} and no 'other'")
    return _parse_nodes(chosen, args, depth + 1)[0]


def _render_number(value) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MessageFormatError(f"number argument must be numeric, got {value!r}")
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise MessageFormatError("NaN/inf not formattable")
        text = repr(value)
    else:
        text = str(value)
    return text


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

@dataclass
class I18nManager:
    """Message catalogs + plural rules for a fixed locale set."""

    default_locale: str = "en"
    _locales: Dict[str, LocaleRecord] = field(default_factory=dict,
                                             init=False, repr=False)
    _catalogs: Dict[str, Dict[str, str]] = field(default_factory=dict,
                                                init=False, repr=False)
    _active: Optional[str] = field(default=None, init=False, repr=False)
    _last_seq: int = field(default=0, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock,
                                   init=False, repr=False)
    _audit: list = field(default_factory=list, init=False, repr=False)

    def __post_init__(self):
        tag = _normalize_tag(self.default_locale)
        object.__setattr__(self, "default_locale", tag)

    # -- seq discipline -----------------------------------------------------
    def _next_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SequenceError(f"seq must be int, got {seq!r}")
        if seq <= self._last_seq:
            raise SequenceError(f"seq {seq} not greater than {self._last_seq}")
        self._last_seq = seq
        return seq

    # -- locales ------------------------------------------------------------
    def add_locale(self, tag: str, seq: int,
                   display_name: Optional[str] = None) -> LocaleRecord:
        with self._lock:
            self._next_seq(seq)
            tag = _normalize_tag(tag)
            if tag in self._locales:
                raise DuplicateLocaleError(f"locale already added: {tag}")
            name = display_name if display_name is not None else tag
            if not isinstance(name, str) or not name:
                raise InvalidTagError("display_name must be a non-empty string")
            rec = LocaleRecord(
                tag=tag, display_name=name, seq=seq,
                digest=_digest(tag, f"{name}\x00{seq}"))
            self._locales[tag] = rec
            self._emit("locale-added", seq, tag, rec.digest)
            return rec

    def locales(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._locales))

    def has_locale(self, tag: str) -> bool:
        with self._lock:
            return _normalize_tag(tag) in self._locales

    def locale(self, tag: Optional[str] = None, seq: Optional[int] = None) -> str:
        """Get (tag=None) or set the active locale."""
        with self._lock:
            if tag is None:
                return self._active or self.default_locale
            if seq is None:
                raise SequenceError("setting locale requires a seq")
            self._next_seq(seq)
            tag = _normalize_tag(tag)
            if tag not in self._locales:
                raise UnknownLocaleError(f"unknown locale: {tag}")
            self._active = tag
            self._emit("locale-set", seq, tag, "")
            return self._active

    # -- catalogs -----------------------------------------------------------
    def add_messages(self, tag: str, messages: Mapping[str, str],
                     seq: int) -> CatalogRecord:
        with self._lock:
            self._next_seq(seq)
            tag = _normalize_tag(tag)
            if tag not in self._locales:
                raise UnknownLocaleError(f"unknown locale: {tag}")
            if not isinstance(messages, Mapping) or not messages:
                raise InvalidCatalogError("messages must be a non-empty mapping")
            clean: Dict[str, str] = {}
            for k, v in messages.items():
                if not isinstance(k, str) or not k:
                    raise InvalidCatalogError(f"bad message key: {k!r}")
                if not isinstance(v, str):
                    raise InvalidCatalogError(f"bad message for {k!r}")
                clean[k] = v
            self._catalogs.setdefault(tag, {}).update(clean)
            keys = sorted(self._catalogs[tag])
            body = "\x00".join(f"{k}={self._catalogs[tag][k]}" for k in keys)
            rec = CatalogRecord(
                tag=tag, key_count=len(keys), seq=seq,
                digest=_digest(tag, body))
            self._emit("catalog-added", seq, tag, rec.digest)
            return rec

    def _resolve(self, key: str, locale: Optional[str]) -> Tuple[str, str]:
        """Return (tag, pattern) through the fallback chain."""
        start = _normalize_tag(locale) if locale else (self._active or self.default_locale)
        chain = list(dict.fromkeys(
            list(_tag_bases(start)) + [self.default_locale]))
        for tag in chain:
            cat = self._catalogs.get(tag)
            if cat and key in cat:
                return tag, cat[key]
        raise MissingMessageError(
            f"key {key!r} missing in {start} and fallbacks")

    def _plural_rule(self, tag: str):
        for base in _tag_bases(tag):
            if base in PLURAL_RULES:
                return PLURAL_RULES[base][0]
        return _rule_other_only

    # -- public ops ---------------------------------------------------------
    def translate(self, key: str, seq: int, *,
                  locale: Optional[str] = None,
                  args: Optional[Mapping[str, object]] = None) -> str:
        with self._lock:
            self._next_seq(seq)
            if not isinstance(key, str) or not key:
                raise MissingMessageError(f"bad key: {key!r}")
            tag, pattern = self._resolve(key, locale)
            merged: Dict[str, object] = {"\x00rule": self._plural_rule(tag)}
            if args:
                if not isinstance(args, Mapping):
                    raise MessageFormatError("args must be a mapping")
                for k, v in args.items():
                    if not isinstance(k, str) or k.startswith("\x00"):
                        raise MessageFormatError(f"bad arg name: {k!r}")
                    merged[k] = v
            text = _format_message(pattern, merged)
            self._emit("translated", seq, tag, _digest(tag, f"{key}\x00{text}"))
            return text

    def plural(self, n: int, seq: int, *,
               locale: Optional[str] = None) -> PluralCategory:
        with self._lock:
            self._next_seq(seq)
            count = _check_count(n)
            tag = _normalize_tag(locale) if locale else (self._active or self.default_locale)
            rule = self._plural_rule(tag)
            cat = rule(count)
            self._emit("plural-resolved", seq, tag, "")
            return PluralCategory(locale=tag, count=count, category=cat, seq=seq)

    # -- audit --------------------------------------------------------------
    def _emit(self, kind: str, seq: int, tag: str, digest: str) -> None:
        self._audit.append({
            "kind": kind, "seq": seq, "locale": tag, "digest": digest,
            "version": VERSION, "schema": SCHEMA,
        })

    def audit_log(self):
        with self._lock:
            return tuple(self._audit)


def i18n_manager_audit_event(kind: str, seq: int, tag: str = "",
                             digest: str = "") -> dict:
    """Shape an ``audit.ndjson/1`` record for this module."""
    allowed = {"locale-added", "catalog-added", "locale-set",
               "translated", "plural-resolved", "rejected"}
    if kind not in allowed:
        raise I18nError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise I18nError(f"bad seq: {seq!r}")
    return {"kind": f"i18n.{kind}", "seq": seq, "locale": tag,
            "digest": digest, "version": VERSION, "schema": SCHEMA}


def main() -> None:
    m = I18nManager(default_locale="en")
    m.add_locale("en", 1, display_name="English")
    m.add_locale("ru", 2, display_name="Русский")
    m.add_messages("en", {
        "hello": "Hello, {name}!",
        "items": "{n, plural, one {# item} other {# items}}",
        "inbox": "{g, select, male {He has} female {She has} other {They have}} {n} messages",
    }, 3)
    m.add_messages("ru", {
        "items": "{n, plural, one {# товар} few {# товара} many {# товаров} other {# товара}}",
    }, 4)
    assert m.translate("hello", 5, args={"name": "Ada"}) == "Hello, Ada!"
    assert m.translate("items", 6, args={"n": 1}) == "1 item"
    assert m.translate("items", 7, args={"n": 5}) == "5 items"
    assert m.translate("items", 8, args={"n": 1}, locale="ru") == "1 товар"
    assert m.translate("items", 9, args={"n": 3}, locale="ru") == "3 товара"
    assert m.translate("items", 10, args={"n": 11}, locale="ru") == "11 товаров"
    assert m.plural(1, 11).category == "one"
    assert m.plural(2, 12).category == "other"
    assert m.plural(5, 13, locale="ru").category == "many"
    assert m.locale("ru", 14) == "ru"
    assert m.locale() == "ru"
    print("i18n-manager OK: locales, catalogs, translate, plural, fallback")


if __name__ == "__main__":
    main()
