"""CardDAV-shaped contact management, in-memory.

Research note: CardDAV (RFC 6352) stores contacts as vCards (RFC 6350,
version 4.0) on the server; the client syncs address books via HTTP. The
load-bearing production concerns, all kept here:

* **vCard rendering** -- every contact renders to a deterministic vCard
  4.0 text block (FN/N/ORG/EMAIL/TEL/ADR), so the stored record pins
  exactly what a CardDAV client would see.
* **Search** -- case-folded substring match across name, emails, phones,
  and org; the search report lists matched contact ids only.
* **Groups** -- named distribution lists holding contact ids; membership
  edits are pinned per mutation and stay consistent when a contact is
  removed (no dangling member ids).
* **Strict seqs** -- every mutation takes a caller-supplied strictly
  increasing int seq; the module never touches the wall clock.

Honest scope: this is *bookkeeping* over host-reported contact data, not
a CardDAV server. There is no HTTP layer, no ETag/CTag sync, no TLS; it
cannot prove an email address or phone number is real (host-reported
GIGO), and search matches text, never intent. Real deployments front
this with a real CardDAV implementation and record digests here.

Version pin: contacts-manager.v1
Schema pin: northstar.contacts-manager.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
CONTACTS_MANAGER_VERSION = "contacts-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.contacts-manager.v1"

#: vCard fields this module knows how to render.
_VCARD_KINDS: FrozenSet[str] = frozenset({"email", "phone"})

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9 .\-()]*$")


class ContactsManagerError(Exception):
    """Base error for contact-management misuse or constraint violations."""


class DuplicateContactError(ContactsManagerError):
    """A contact_id is already in use."""


class UnknownContactError(ContactsManagerError):
    """A contact_id was not found."""


class DuplicateGroupError(ContactsManagerError):
    """A group_id is already in use."""


class UnknownGroupError(ContactsManagerError):
    """A group_id was not found."""


class NotMemberError(ContactsManagerError):
    """A contact is not a member of the group."""


class ValidationError(ContactsManagerError):
    """A field failed fail-closed validation."""


class SeqOrderError(ContactsManagerError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_id(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{role} must be a non-empty str")
    return value.strip()


def _check_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("name must be a non-empty str")
    return value.strip()


def _check_emails(emails: Any) -> Tuple[str, ...]:
    if emails is None:
        return ()
    if not isinstance(emails, (list, tuple)):
        raise ValidationError("emails must be a list/tuple of str")
    out = []
    for e in emails:
        if not isinstance(e, str) or not _EMAIL_RE.match(e.strip()):
            raise ValidationError(f"bad email address: {e!r}")
        out.append(e.strip().lower())
    return tuple(out)


def _check_phones(phones: Any) -> Tuple[str, ...]:
    if phones is None:
        return ()
    if not isinstance(phones, (list, tuple)):
        raise ValidationError("phones must be a list/tuple of str")
    out = []
    for p in phones:
        if not isinstance(p, str) or not _PHONE_RE.match(p.strip()):
            raise ValidationError(f"bad phone number: {p!r}")
        out.append(p.strip())
    return tuple(out)


def _check_str_opt(value: Any, role: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{role} must be a str or None")
    v = value.strip()
    return v or None


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContactRecord:
    """One pinned contact: name, emails, phones, org/address metadata."""

    contact_id: str
    name: str
    emails: Tuple[str, ...]
    phones: Tuple[str, ...]
    org: Optional[str]
    address: Optional[str]
    note: Optional[str]
    digest: str
    seq: int
    version: str = CONTACTS_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "contact_id": self.contact_id,
            "name": self.name,
            "emails": list(self.emails),
            "phones": list(self.phones),
            "org": self.org,
            "address": self.address,
            "note": self.note,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin over the contact body."""
        body = {
            "contact_id": self.contact_id,
            "name": self.name,
            "emails": list(self.emails),
            "phones": list(self.phones),
            "org": self.org,
            "address": self.address,
            "note": self.note,
        }
        return _pin(body) == self.digest


@dataclass(frozen=True)
class GroupRecord:
    """One pinned contact group with its member contact ids."""

    group_id: str
    name: str
    members: Tuple[str, ...]
    digest: str
    seq: int
    version: str = CONTACTS_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "members": list(self.members),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        body = {
            "group_id": self.group_id,
            "name": self.name,
            "members": list(self.members),
        }
        return _pin(body) == self.digest


@dataclass(frozen=True)
class SearchReport:
    """Result of a search: matched contact ids, digest-pinned."""

    query: str
    matches: Tuple[str, ...]
    seq: int
    version: str = CONTACTS_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "matches": list(self.matches),
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class VCardDocument:
    """A rendered vCard 4.0 text block for one contact, digest-pinned."""

    contact_id: str
    text: str
    digest: str
    seq: int
    version: str = CONTACTS_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "contact_id": self.contact_id,
            "text": self.text,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self, text: str) -> bool:
        """Re-derive the vCard pin for a candidate text block."""
        return _pin({"vcard": text}) == self.digest


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class ContactsManager:
    """CardDAV-shaped contact bookkeeping, in-memory."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._contacts: Dict[str, ContactRecord] = {}
        self._groups: Dict[str, GroupRecord] = {}
        self._audit: List[Dict[str, Any]] = []

    def _advance(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    # -- contacts ----------------------------------------------------------

    def add(
        self,
        contact_id: str,
        name: str,
        seq: int,
        emails: Optional[Sequence[str]] = None,
        phones: Optional[Sequence[str]] = None,
        org: Optional[str] = None,
        address: Optional[str] = None,
        note: Optional[str] = None,
    ) -> ContactRecord:
        """Add a contact; ids are unique and never recycled."""
        with self._lock:
            seq = self._advance(seq)
            contact_id = _check_id(contact_id, "contact_id")
            if contact_id in self._contacts:
                raise DuplicateContactError(f"duplicate contact_id: {contact_id}")
            name = _check_name(name)
            emails_t = _check_emails(emails)
            phones_t = _check_phones(phones)
            org_s = _check_str_opt(org, "org")
            addr_s = _check_str_opt(address, "address")
            note_s = _check_str_opt(note, "note")
            body = {
                "contact_id": contact_id,
                "name": name,
                "emails": list(emails_t),
                "phones": list(phones_t),
                "org": org_s,
                "address": addr_s,
                "note": note_s,
            }
            record = ContactRecord(
                contact_id=contact_id,
                name=name,
                emails=emails_t,
                phones=phones_t,
                org=org_s,
                address=addr_s,
                note=note_s,
                digest=_pin(body),
                seq=seq,
            )
            self._contacts[contact_id] = record
            self._audit.append(
                contacts_manager_audit_event("added", seq, contact_id)
            )
            return record

    def update(
        self,
        contact_id: str,
        seq: int,
        name: Optional[str] = None,
        emails: Optional[Sequence[str]] = None,
        phones: Optional[Sequence[str]] = None,
        org: Optional[str] = None,
        address: Optional[str] = None,
        note: Optional[str] = None,
    ) -> ContactRecord:
        """Replace any provided fields of an existing contact."""
        with self._lock:
            seq = self._advance(seq)
            contact_id = _check_id(contact_id, "contact_id")
            old = self._contacts.get(contact_id)
            if old is None:
                raise UnknownContactError(f"unknown contact_id: {contact_id}")
            name_s = _check_name(name) if name is not None else old.name
            emails_t = (
                _check_emails(emails) if emails is not None else old.emails
            )
            phones_t = (
                _check_phones(phones) if phones is not None else old.phones
            )
            org_s = _check_str_opt(org, "org") if org is not None else old.org
            addr_s = (
                _check_str_opt(address, "address")
                if address is not None
                else old.address
            )
            note_s = _check_str_opt(note, "note") if note is not None else old.note
            body = {
                "contact_id": contact_id,
                "name": name_s,
                "emails": list(emails_t),
                "phones": list(phones_t),
                "org": org_s,
                "address": addr_s,
                "note": note_s,
            }
            record = ContactRecord(
                contact_id=contact_id,
                name=name_s,
                emails=emails_t,
                phones=phones_t,
                org=org_s,
                address=addr_s,
                note=note_s,
                digest=_pin(body),
                seq=seq,
            )
            self._contacts[contact_id] = record
            self._audit.append(
                contacts_manager_audit_event("updated", seq, contact_id)
            )
            return record

    def remove(self, contact_id: str, seq: int) -> None:
        """Remove a contact; membership is dropped from every group."""
        with self._lock:
            seq = self._advance(seq)
            contact_id = _check_id(contact_id, "contact_id")
            if contact_id not in self._contacts:
                raise UnknownContactError(f"unknown contact_id: {contact_id}")
            del self._contacts[contact_id]
            for gid, grp in list(self._groups.items()):
                if contact_id in grp.members:
                    members = tuple(m for m in grp.members if m != contact_id)
                    body = {
                        "group_id": grp.group_id,
                        "name": grp.name,
                        "members": list(members),
                    }
                    self._groups[gid] = GroupRecord(
                        group_id=grp.group_id,
                        name=grp.name,
                        members=members,
                        digest=_pin(body),
                        seq=seq,
                    )
            self._audit.append(
                contacts_manager_audit_event("removed", seq, contact_id)
            )

    def contact(self, contact_id: str) -> ContactRecord:
        """Look up a contact by id."""
        contact_id = _check_id(contact_id, "contact_id")
        with self._lock:
            try:
                return self._contacts[contact_id]
            except KeyError:
                raise UnknownContactError(
                    f"unknown contact_id: {contact_id}"
                ) from None

    def contacts(self) -> List[str]:
        """Sorted list of contact ids."""
        with self._lock:
            return sorted(self._contacts)

    # -- search ------------------------------------------------------------

    def search(self, query: str, seq: int) -> SearchReport:
        """Case-folded substring search over name, emails, phones, org."""
        with self._lock:
            seq = self._advance(seq)
            if not isinstance(query, str) or not query.strip():
                raise ValidationError("query must be a non-empty str")
            q = query.strip().casefold()
            matches: List[str] = []
            for cid, rec in self._contacts.items():
                haystacks = [rec.name.casefold()]
                haystacks.extend(e.casefold() for e in rec.emails)
                haystacks.extend(p.casefold() for p in rec.phones)
                if rec.org:
                    haystacks.append(rec.org.casefold())
                if any(q in h for h in haystacks):
                    matches.append(cid)
            matches.sort()
            report = SearchReport(query=query.strip(), matches=tuple(matches), seq=seq)
            self._audit.append(
                contacts_manager_audit_event("searched", seq, "")
            )
            return report

    # -- vCard -------------------------------------------------------------

    def to_vcard(self, contact_id: str, seq: int) -> VCardDocument:
        """Render a deterministic vCard 4.0 block for a contact."""
        with self._lock:
            seq = self._advance(seq)
            contact_id = _check_id(contact_id, "contact_id")
            rec = self._contacts.get(contact_id)
            if rec is None:
                raise UnknownContactError(f"unknown contact_id: {contact_id}")
            lines = [
                "BEGIN:VCARD",
                "VERSION:4.0",
                f"FN:{_escape_vcard(rec.name)}",
            ]
            if rec.org:
                lines.append(f"ORG:{_escape_vcard(rec.org)}")
            for e in rec.emails:
                lines.append(f"EMAIL:{_escape_vcard(e)}")
            for p in rec.phones:
                lines.append(f"TEL:{_escape_vcard(p)}")
            if rec.address:
                lines.append(f"ADR:;;{_escape_vcard(rec.address)};;;;")
            if rec.note:
                lines.append(f"NOTE:{_escape_vcard(rec.note)}")
            lines.append(f"UID:{rec.contact_id}")
            lines.append("END:VCARD")
            text = "\r\n".join(lines) + "\r\n"
            doc = VCardDocument(
                contact_id=contact_id,
                text=text,
                digest=_pin({"vcard": text}),
                seq=seq,
            )
            self._audit.append(
                contacts_manager_audit_event("rendered", seq, contact_id)
            )
            return doc

    # -- groups ------------------------------------------------------------

    def group(
        self,
        group_id: str,
        name: str,
        seq: int,
        members: Optional[Sequence[str]] = None,
    ) -> GroupRecord:
        """Create a named contact group; initial members must exist."""
        with self._lock:
            seq = self._advance(seq)
            group_id = _check_id(group_id, "group_id")
            if group_id in self._groups:
                raise DuplicateGroupError(f"duplicate group_id: {group_id}")
            name = _check_name(name)
            members_t = self._resolve_members(members)
            body = {
                "group_id": group_id,
                "name": name,
                "members": list(members_t),
            }
            record = GroupRecord(
                group_id=group_id,
                name=name,
                members=members_t,
                digest=_pin(body),
                seq=seq,
            )
            self._groups[group_id] = record
            self._audit.append(
                contacts_manager_audit_event("grouped", seq, group_id)
            )
            return record

    def add_member(self, group_id: str, contact_id: str, seq: int) -> GroupRecord:
        """Add a contact to a group (idempotent)."""
        with self._lock:
            seq = self._advance(seq)
            group_id = _check_id(group_id, "group_id")
            contact_id = _check_id(contact_id, "contact_id")
            grp = self._groups.get(group_id)
            if grp is None:
                raise UnknownGroupError(f"unknown group_id: {group_id}")
            if contact_id not in self._contacts:
                raise UnknownContactError(f"unknown contact_id: {contact_id}")
            members = (
                grp.members
                if contact_id in grp.members
                else grp.members + (contact_id,)
            )
            record = self._remake_group(grp, members, seq)
            self._audit.append(
                contacts_manager_audit_event("member-added", seq, group_id)
            )
            return record

    def remove_member(self, group_id: str, contact_id: str, seq: int) -> GroupRecord:
        """Remove a contact from a group; non-members raise fail-closed."""
        with self._lock:
            seq = self._advance(seq)
            group_id = _check_id(group_id, "group_id")
            contact_id = _check_id(contact_id, "contact_id")
            grp = self._groups.get(group_id)
            if grp is None:
                raise UnknownGroupError(f"unknown group_id: {group_id}")
            if contact_id not in grp.members:
                raise NotMemberError(f"{contact_id} is not in group {group_id}")
            members = tuple(m for m in grp.members if m != contact_id)
            record = self._remake_group(grp, members, seq)
            self._audit.append(
                contacts_manager_audit_event("member-removed", seq, group_id)
            )
            return record

    def group_record(self, group_id: str) -> GroupRecord:
        """Look up a group by id."""
        group_id = _check_id(group_id, "group_id")
        with self._lock:
            try:
                return self._groups[group_id]
            except KeyError:
                raise UnknownGroupError(f"unknown group_id: {group_id}") from None

    def groups(self) -> List[str]:
        """Sorted list of group ids."""
        with self._lock:
            return sorted(self._groups)

    # -- internals ---------------------------------------------------------

    def _resolve_members(
        self, members: Optional[Sequence[str]]
    ) -> Tuple[str, ...]:
        if members is None:
            return ()
        if not isinstance(members, (list, tuple)):
            raise ValidationError("members must be a list/tuple of contact ids")
        seen: List[str] = []
        for m in members:
            mid = _check_id(m, "member contact_id")
            if mid not in self._contacts:
                raise UnknownContactError(f"unknown member contact_id: {mid}")
            if mid not in seen:
                seen.append(mid)
        return tuple(seen)

    def _remake_group(
        self, grp: GroupRecord, members: Tuple[str, ...], seq: int
    ) -> GroupRecord:
        body = {
            "group_id": grp.group_id,
            "name": grp.name,
            "members": list(members),
        }
        record = GroupRecord(
            group_id=grp.group_id,
            name=grp.name,
            members=members,
            digest=_pin(body),
            seq=seq,
        )
        self._groups[grp.group_id] = record
        return record

    # -- audit -------------------------------------------------------------

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


def _escape_vcard(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace(";", "\\;")
        .replace(",", "\\,")
    )


def contacts_manager_audit_event(
    kind: str, seq: int, target_id: str
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for this module (ids/digests, never PII)."""
    if kind not in (
        "added",
        "updated",
        "removed",
        "searched",
        "rendered",
        "grouped",
        "member-added",
        "member-removed",
        "rejected",
    ):
        raise ValidationError(f"unknown audit kind: {kind}")
    _check_seq(seq)
    if not isinstance(target_id, str):
        raise ValidationError("target_id must be a str")
    return {
        "kind": kind,
        "seq": seq,
        "target_id": target_id,
        "module": "contacts-manager",
        "version": CONTACTS_MANAGER_VERSION,
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    cm = ContactsManager()
    rec = cm.add("c1", "Ada Lovelace", 1, emails=["ada@example.com"],
                 phones=["+14155550101"], org="Analytical Engines")
    assert rec.verify()
    rep = cm.search("ada", 2)
    assert rep.matches == ("c1",)
    doc = cm.to_vcard("c1", 3)
    assert doc.verify(doc.text) and "BEGIN:VCARD" in doc.text
    grp = cm.group("g1", "Friends", 4, members=["c1"])
    assert grp.verify() and grp.members == ("c1",)
    grp = cm.remove_member("g1", "c1", 5)
    assert grp.members == ()
    print("contacts-manager OK: add, search, vcard, groups, pins")


if __name__ == "__main__":
    main()
