"""User profile records with per-field privacy levels, in-memory.

Research note: Profile fields. The load-bearing shape is the one every
identity provider converges on -- a small set of named claims about a
person (OpenID Connect Core 5.1 userinfo: name, preferred_username,
picture, email, phone_number, locale, zoneinfo), plus provider-specific
extensions. What the host stores is always a *projection* of what the
user consented to reveal; the privacy model here keeps that projection
honest:

* **Per-field visibility** -- each field pins one of ``public``,
  ``contacts``, or ``private``. Defaults are fail-closed (private) for
  identifiers (email, phone, locale, timezone, custom fields) and
  fail-open only for the display surface (display_name, bio,
  avatar_ref), which must be public to be useful.
* **Relation-based views** -- ``visibility()`` renders what a viewer
  with relation ``self`` / ``contacts`` / ``public`` may see; the
  rendered view pins the fields shown and a digest of the source
  record, so a consumer can re-verify what the view *claims* to show
  against the profile's digest.
* **Digest-pinned mutations** -- every create/update re-validates all
  fields, recomputes the record digest, and chains ``prev_digest``; a
  tampered record fails ``verify()``.
* **Strict seqs** -- every call takes a caller-supplied strictly
  increasing int seq (reads too: ``visibility()`` emits an audit event);
  the module never touches the wall clock.

Honest scope: this is *bookkeeping* over host-supplied profile data,
not an identity provider. It cannot prove an email or phone number is
real (host-reported GIGO), cannot enforce who counts as a "contact"
(the host's contact graph is outside this module), and the audit trail
carries ids and digests only -- never PII. Real deployments front this
with a real IdP and record digests here.

Version pin: user-profile.v1
Schema pin: northstar.user-profile.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
USER_PROFILE_VERSION = "user-profile.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.user-profile.v1"

#: Visibility levels a field may carry.
VISIBILITY_LEVELS: Tuple[str, ...] = ("public", "contacts", "private")

#: Viewer relations understood by :meth:`UserProfileManager.visibility`.
VIEWER_RELATIONS: Tuple[str, ...] = ("self", "contacts", "public")

#: Core profile fields (custom fields are ``custom:<key>``).
CORE_FIELDS: Tuple[str, ...] = (
    "display_name",
    "bio",
    "email",
    "phone",
    "avatar_ref",
    "locale",
    "timezone",
)

#: Default visibility per core field; custom fields default to private.
_DEFAULT_VISIBILITY: Dict[str, str] = {
    "display_name": "public",
    "bio": "public",
    "avatar_ref": "public",
    "email": "private",
    "phone": "private",
    "locale": "private",
    "timezone": "private",
}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9 .\-()]*$")
_LOCALE_RE = re.compile(r"^[a-z]{2,3}(-[A-Z][a-z]{3})?(-[A-Z]{2}|[0-9]{3})?$")
_TZ_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z][A-Za-z0-9_+\-]*)+$|^UTC([+-][0-9]{1,2}(:[0-9]{2})?)?$")
_CUSTOM_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

_MAX_DISPLAY_NAME = 128
_MAX_BIO = 1024
_MAX_EMAIL = 254
_MAX_PHONE = 32
_MAX_AVATAR_REF = 512
_MAX_LOCALE = 16
_MAX_TZ = 64
_MAX_CUSTOM_VALUE = 256


class UserProfileError(Exception):
    """Base error for profile misuse or constraint violations."""


class DuplicateProfileError(UserProfileError):
    """A profile_id is already in use."""


class UnknownProfileError(UserProfileError):
    """A profile_id was not found."""


class ValidationError(UserProfileError):
    """A field or argument failed fail-closed validation."""


class SeqOrderError(UserProfileError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_profile_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("profile_id must be a non-empty str")
    return value.strip()


def _check_relation(relation: Any) -> str:
    if relation not in VIEWER_RELATIONS:
        raise ValidationError(
            f"relation must be one of {VIEWER_RELATIONS}, got {relation!r}"
        )
    return relation


def _check_visibility_level(level: Any) -> str:
    if level not in VISIBILITY_LEVELS:
        raise ValidationError(
            f"visibility level must be one of {VISIBILITY_LEVELS}, got {level!r}"
        )
    return level


def _check_field_name(name: Any) -> str:
    if not isinstance(name, str):
        raise ValidationError(f"field name must be a str, got {name!r}")
    if name in CORE_FIELDS:
        return name
    if name.startswith("custom:"):
        key = name[len("custom:") :]
        if not _CUSTOM_KEY_RE.match(key):
            raise ValidationError(f"bad custom field key: {key!r}")
        return name
    raise ValidationError(f"unknown field: {name!r}")


def _check_value(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"field {name!r} value must be a str")
    if name == "display_name":
        if not value.strip() or len(value) > _MAX_DISPLAY_NAME:
            raise ValidationError("display_name must be non-empty, <= 128 chars")
    elif name == "bio":
        if len(value) > _MAX_BIO:
            raise ValidationError("bio must be <= 1024 chars")
    elif name == "email":
        if len(value) > _MAX_EMAIL or not _EMAIL_RE.match(value.strip()):
            raise ValidationError(f"bad email address: {value!r}")
        value = value.strip().lower()
    elif name == "phone":
        if len(value) > _MAX_PHONE or not _PHONE_RE.match(value.strip()):
            raise ValidationError(f"bad phone number: {value!r}")
        value = value.strip()
    elif name == "avatar_ref":
        if len(value) > _MAX_AVATAR_REF or not value.strip():
            raise ValidationError("avatar_ref must be non-empty, <= 512 chars")
        value = value.strip()
    elif name == "locale":
        if len(value) > _MAX_LOCALE or not _LOCALE_RE.match(value.strip()):
            raise ValidationError(f"bad locale: {value!r}")
        value = value.strip()
    elif name == "timezone":
        if len(value) > _MAX_TZ or not _TZ_RE.match(value.strip()):
            raise ValidationError(f"bad timezone: {value!r}")
        value = value.strip()
    elif name.startswith("custom:"):
        if len(value) > _MAX_CUSTOM_VALUE:
            raise ValidationError(f"custom field {name!r} value must be <= 256 chars")
    else:  # pragma: no cover - _check_field_name rejects unknown names first
        raise ValidationError(f"unknown field: {name!r}")
    return value


def _record_payload(
    profile_id: str,
    fields: Tuple[Tuple[str, str], ...],
    visibility: Tuple[Tuple[str, str], ...],
    seq: int,
    prev_digest: str,
) -> Dict[str, Any]:
    return {
        "schema": SCHEMA_PIN,
        "version": USER_PROFILE_VERSION,
        "profile_id": profile_id,
        "fields": sorted(fields),
        "visibility": sorted(visibility),
        "seq": seq,
        "prev_digest": prev_digest,
    }


def _digest_of(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(jcs_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class UserProfile:
    """One digest-pinned user profile record."""

    profile_id: str
    fields: Tuple[Tuple[str, str], ...] = ()
    visibility: Tuple[Tuple[str, str], ...] = ()
    seq: int = 0
    prev_digest: str = ""
    digest: str = ""

    def field(self, name: str) -> Optional[str]:
        """Return the value of a set field, else None."""
        for k, v in self.fields:
            if k == name:
                return v
        return None

    def level(self, name: str) -> str:
        """Return the visibility level of a field (private if unset)."""
        for k, v in self.visibility:
            if k == name:
                return v
        return "private"

    def verify(self) -> bool:
        """Recompute the digest chain head and compare (fail-closed)."""
        if not self.digest or not self.profile_id:
            return False
        payload = _record_payload(
            self.profile_id, self.fields, self.visibility, self.seq, self.prev_digest
        )
        return _digest_of(payload) == self.digest


@dataclass(frozen=True)
class ProfileView:
    """What ``visibility()`` discloses to a given viewer relation.

    Carries no more than the visible fields plus pins of the source
    record (profile digest + seq) so a consumer can re-verify the claim
    against :meth:`UserProfile.verify`.
    """

    profile_id: str
    relation: str
    fields: Tuple[Tuple[str, str], ...] = ()
    source_digest: str = ""
    seq: int = 0
    digest: str = ""

    def verify(self, profile: UserProfile) -> bool:
        """Check this view against its source profile record."""
        if profile.profile_id != self.profile_id:
            return False
        if not profile.verify():
            return False
        if self.source_digest != profile.digest:
            return False
        payload = {
            "schema": SCHEMA_PIN,
            "profile_id": self.profile_id,
            "relation": self.relation,
            "fields": sorted(self.fields),
            "source_digest": self.source_digest,
            "seq": self.seq,
        }
        return _digest_of(payload) == self.digest


def user_profile_audit_event(
    kind: str, seq: int, target_id: str
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for this module (ids/digests, never PII)."""
    if kind not in ("created", "updated", "visibility-checked", "rejected"):
        raise ValidationError(f"unknown audit kind: {kind}")
    _check_seq(seq)
    if not isinstance(target_id, str):
        raise ValidationError("target_id must be a str")
    return {
        "kind": kind,
        "seq": seq,
        "target_id": target_id,
        "module": "user-profile",
        "version": USER_PROFILE_VERSION,
        "schema": "audit.ndjson/1",
    }


class UserProfileManager:
    """In-memory manager for digest-pinned user profiles."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._profiles: Dict[str, UserProfile] = {}
        self._last_seq: Dict[str, int] = {}
        self._audit: Tuple[Dict[str, Any], ...] = ()

    # -- seq / audit internals -----------------------------------------

    def _note_seq(self, profile_id: str, seq: int) -> None:
        last = self._last_seq.get(profile_id, -1)
        if seq <= last:
            raise SeqOrderError(
                f"seq {seq} must be strictly greater than last {last} "
                f"for profile {profile_id!r}"
            )
        self._last_seq[profile_id] = seq

    def _audit_note(self, kind: str, seq: int, profile_id: str) -> None:
        self._audit = self._audit + (
            user_profile_audit_event(kind, seq, profile_id),
        )

    def audit_trail(self) -> Tuple[Dict[str, Any], ...]:
        """Return the append-only audit records emitted so far."""
        with self._lock:
            return self._audit

    # -- reads ----------------------------------------------------------

    def profile(self, profile_id: str) -> UserProfile:
        """Return the full record for a profile_id (host-internal read)."""
        pid = _check_profile_id(profile_id)
        with self._lock:
            try:
                return self._profiles[pid]
            except KeyError:
                raise UnknownProfileError(f"unknown profile_id: {pid!r}")

    # -- mutations ------------------------------------------------------

    def create(
        self,
        profile_id: str,
        display_name: str,
        seq: int,
        *,
        bio: str = "",
        email: str = "",
        phone: str = "",
        avatar_ref: str = "",
        locale: str = "",
        timezone: str = "",
        custom_fields: Tuple[Tuple[str, str], ...] = (),
        visibility_overrides: Tuple[Tuple[str, str], ...] = (),
    ) -> UserProfile:
        """Create a profile. Unset optional fields are stored as empty (undisclosed)."""
        pid = _check_profile_id(profile_id)
        _check_seq(seq)
        if not isinstance(display_name, str) or not display_name.strip():
            raise ValidationError("display_name is required and must be non-empty")
        raw: Dict[str, str] = {
            "display_name": display_name,
            "bio": bio,
            "email": email,
            "phone": phone,
            "avatar_ref": avatar_ref,
            "locale": locale,
            "timezone": timezone,
        }
        fields: Dict[str, str] = {}
        for name, value in raw.items():
            if not isinstance(value, str):
                raise ValidationError(f"field {name!r} value must be a str")
            if not value.strip():
                continue  # unset -> undisclosed
            fields[name] = _check_value(name, value)
        if not isinstance(custom_fields, (tuple, list)):
            raise ValidationError("custom_fields must be a tuple/list of pairs")
        for pair in custom_fields:
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                raise ValidationError("custom_fields entries must be (key, value) pairs")
            key, value = pair
            name = _check_field_name(f"custom:{key}")
            checked = _check_value(name, value)
            if not checked:
                raise ValidationError(f"custom field {key!r} value must be non-empty")
            if name in fields:
                raise ValidationError(f"duplicate custom field key: {key!r}")
            fields[name] = checked
        visibility: Dict[str, str] = {}
        for name in fields:
            visibility[name] = _DEFAULT_VISIBILITY.get(name, "private")
        if not isinstance(visibility_overrides, (tuple, list)):
            raise ValidationError("visibility_overrides must be a tuple/list of pairs")
        for pair in visibility_overrides:
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                raise ValidationError(
                    "visibility_overrides entries must be (field, level) pairs"
                )
            fname, level = pair
            name = _check_field_name(fname)
            if name not in fields:
                raise ValidationError(
                    f"cannot set visibility on unset field: {fname!r}"
                )
            visibility[name] = _check_visibility_level(level)

        with self._lock:
            if pid in self._profiles:
                raise DuplicateProfileError(f"duplicate profile_id: {pid!r}")
            self._note_seq(pid, seq)
            field_t = tuple(sorted(fields.items()))
            vis_t = tuple(sorted(visibility.items()))
            payload = _record_payload(pid, field_t, vis_t, seq, "")
            rec = UserProfile(
                profile_id=pid,
                fields=field_t,
                visibility=vis_t,
                seq=seq,
                prev_digest="",
                digest=_digest_of(payload),
            )
            self._profiles[pid] = rec
            self._audit_note("created", seq, pid)
            return rec

    def update(
        self,
        profile_id: str,
        seq: int,
        *,
        fields: Optional[Mapping[str, str]] = None,
        visibility: Optional[Mapping[str, str]] = None,
    ) -> UserProfile:
        """Mutate set fields / visibility levels; returns the new pinned record.

        An update value of ``""`` clears the field (and drops its visibility
        pin). Visibility levels may be changed only on set fields.
        """
        pid = _check_profile_id(profile_id)
        _check_seq(seq)
        if fields is not None and not isinstance(fields, Mapping):
            raise ValidationError("fields must be a mapping")
        if visibility is not None and not isinstance(visibility, Mapping):
            raise ValidationError("visibility must be a mapping")

        with self._lock:
            old = self.profile(pid)
            self._note_seq(pid, seq)
            cur_fields = dict(old.fields)
            cur_vis = dict(old.visibility)
            for name, value in (fields or {}).items():
                name = _check_field_name(name)
                checked = _check_value(name, value)
                if not checked.strip():
                    cur_fields.pop(name, None)
                    cur_vis.pop(name, None)
                else:
                    cur_fields[name] = checked
                    cur_vis.setdefault(name, _DEFAULT_VISIBILITY.get(name, "private"))
            for name, level in (visibility or {}).items():
                name = _check_field_name(name)
                if name not in cur_fields:
                    raise ValidationError(
                        f"cannot set visibility on unset field: {name!r}"
                    )
                cur_vis[name] = _check_visibility_level(level)
            field_t = tuple(sorted(cur_fields.items()))
            vis_t = tuple(sorted(cur_vis.items()))
            payload = _record_payload(pid, field_t, vis_t, seq, old.digest)
            rec = UserProfile(
                profile_id=pid,
                fields=field_t,
                visibility=vis_t,
                seq=seq,
                prev_digest=old.digest,
                digest=_digest_of(payload),
            )
            self._profiles[pid] = rec
            self._audit_note("updated", seq, pid)
            return rec

    # -- disclosure -----------------------------------------------------

    def visibility(self, profile_id: str, seq: int, relation: str) -> ProfileView:
        """Render what a viewer with ``relation`` may see (audited read)."""
        pid = _check_profile_id(profile_id)
        _check_seq(seq)
        rel = _check_relation(relation)

        with self._lock:
            rec = self.profile(pid)
            self._note_seq(pid, seq)
            shown: Dict[str, str] = {}
            if rel == "self":
                shown = dict(rec.fields)
            else:
                for k, v in rec.fields:
                    lvl = rec.level(k)
                    if lvl == "public":
                        shown[k] = v
                    elif lvl == "contacts" and rel == "contacts":
                        shown[k] = v
            field_t = tuple(sorted(shown.items()))
            payload = {
                "schema": SCHEMA_PIN,
                "profile_id": pid,
                "relation": rel,
                "fields": sorted(field_t),
                "source_digest": rec.digest,
                "seq": seq,
            }
            view = ProfileView(
                profile_id=pid,
                relation=rel,
                fields=field_t,
                source_digest=rec.digest,
                seq=seq,
                digest=_digest_of(payload),
            )
            self._audit_note("visibility-checked", seq, pid)
            return view


def main() -> None:
    m = UserProfileManager()
    rec = m.create(
        "u1",
        "Ada Lovelace",
        1,
        email="ada@example.com",
        phone="+14155550101",
        locale="en-US",
        timezone="America/New_York",
        visibility_overrides=(("email", "contacts"),),
    )
    assert rec.verify()
    assert rec.level("email") == "contacts" and rec.level("phone") == "private"
    rec = m.update("u1", 2, fields={"bio": "first programmer"}, visibility={"phone": "contacts"})
    assert rec.verify() and rec.field("bio") == "first programmer"
    self_view = m.visibility("u1", 3, "self")
    assert self_view.verify(rec) and dict(self_view.fields)["email"] == "ada@example.com"
    pub = m.visibility("u1", 4, "public")
    assert pub.verify(rec) and "email" not in dict(pub.fields)
    con = m.visibility("u1", 5, "contacts")
    assert con.verify(rec) and dict(con.fields)["email"] == "ada@example.com"
    print("user-profile OK: create, update, visibility views, pins")


if __name__ == "__main__":
    main()
