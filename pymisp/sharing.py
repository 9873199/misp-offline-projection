"""Offline, recipient-view sharing projection for MISP events.

The caller supplies the recipient organisations, the instance relationship and
the explicit sharing-group memberships. Nothing is fetched from a MISP server.
The projector resolves distribution 5 through the real container chain, treats
sharing groups as membership sets rather than a numeric distribution value, and
returns either a sanitised MISP JSON event or a pending/denied decision with an
identifier-only audit trail.
"""

from __future__ import annotations

import copy
import hashlib
import json as _json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from .abstract import AbstractMISP, Distribution
from .exceptions import PyMISPError
from .mispevent import (MISPAttribute, MISPEvent, MISPObject,
                        MISPRelationship, MISPSharingGroup, MISPSharingGroupOrg)


SUPPORTED_RECIPIENT_VERSION = '1'
MINIMUM_MISP_VERSION = (2, 4, 0)
MINIMUM_ANALYST_DATA_MISP_VERSION = (2, 4, 186)


class InstanceRelationship(str, Enum):
    """How the recipient instance relates to the instance that produced the event.

    The values describe the recipient's reachable distribution scope, not a
    numeric ordering of distribution levels.
    """

    SAME_INSTANCE = 'same_instance'
    CONNECTED = 'connected'
    ALL_COMMUNITIES = 'all_communities'

    @property
    def accepted_distributions(self) -> frozenset[int]:
        if self is InstanceRelationship.SAME_INSTANCE:
            return frozenset({1, 2, 3})
        if self is InstanceRelationship.CONNECTED:
            return frozenset({2, 3})
        return frozenset({3})

    def __str__(self) -> str:
        return self.value


class SharingDecision(str, Enum):
    ALLOW = 'allow'
    DENY = 'deny'
    PENDING = 'pending'

    def __str__(self) -> str:
        return self.value


class ProjectionStatus(str, Enum):
    ALLOWED = 'allowed'
    PARTIAL = 'partial'
    PENDING = 'pending'
    DENIED = 'denied'

    def __str__(self) -> str:
        return self.value


class ShareAuditEntry(dict[str, Any]):
    """A single projection exclusion.

    Only identifiers and a machine-readable reason are kept. Values, comments,
    names and other event content are deliberately never copied into the audit
    trail.
    """

    kind: str
    reason: str
    uuid: str | None
    id: str | None
    sharing_group_id: str | None

    def __init__(self, kind: str, reason: str, uuid: str | None = None,
                 id: str | None = None, sharing_group_id: str | None = None) -> None:
        super().__init__(kind=kind, reason=reason)
        if uuid is not None:
            self['uuid'] = uuid
        if id is not None:
            self['id'] = id
        if sharing_group_id is not None:
            self['sharing_group_id'] = sharing_group_id
        self.kind = kind
        self.reason = reason
        self.uuid = uuid
        self.id = id
        self.sharing_group_id = sharing_group_id

    def to_dict(self) -> dict[str, Any]:
        return dict(self)


class SharingGroupMember:
    """A member of a sharing group as supplied by the caller."""

    def __init__(self, organisation: Any, extend: bool = False) -> None:
        self.organisation = organisation
        self.extend = bool(extend)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(extend={self.extend})>'


class SharingGroupMembership:
    """Explicit, caller-supplied membership for one sharing group.

    ``members=None`` means the membership table is unavailable and any
    decision that needs it stays pending. An empty sequence is an explicit
    empty membership table and therefore denies access.
    """

    def __init__(self, members: Any = None, *, organisations: Any = None, orgs: Any = None,
                 uuid: str | None = None, name: str | None = None,
                 id: str | int | None = None, owner: Any = None,
                 all_orgs: bool = False, extend: bool = False) -> None:
        if members is None:
            members = organisations if organisations is not None else orgs
        self.members = None if members is None else _normalise_members(members)
        self.uuid = uuid
        self.name = name
        self.id = id
        self.owner = owner
        self.all_orgs = bool(all_orgs)
        self.extend = bool(extend)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(id={self.id}, uuid={self.uuid}, name={self.name}, all_orgs={self.all_orgs})>'


def _as_sequence(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, Mapping, AbstractMISP, SharingGroupMember)):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(value)
    if isinstance(value, Iterable):
        return tuple(value)
    return (value,)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalise_members(value: Any) -> tuple[Any, ...]:
    if isinstance(value, AbstractMISP):
        return _as_sequence(value)
    if isinstance(value, Mapping) and not any(
            key in value for key in ('uuid', 'name', 'id', 'org_id', 'Organisation',
                                     'organisation', 'org')):
        members = []
        for member, info in value.items():
            if isinstance(info, Mapping):
                member_info = dict(info)
                member_text = str(member).strip()
                if _UUID_RE.match(member_text) and 'uuid' not in member_info:
                    member_info['uuid'] = member_text
                elif not _UUID_RE.match(member_text):
                    member_info.setdefault('name', member_text)
                members.append(SharingGroupMember(member_info,
                                                 bool(member_info.get('extend', False))))
            elif isinstance(info, SharingGroupMember):
                members.append(info)
            else:
                members.append(SharingGroupMember(member, bool(info)))
        return tuple(members)
    return _as_sequence(value)


_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')


@dataclass(frozen=True)
class _OrgIdentity:
    uuids: frozenset[str] = frozenset()
    names: frozenset[str] = frozenset()
    ids: frozenset[str] = frozenset()
    tokens: frozenset[str] = frozenset()

    @property
    def is_empty(self) -> bool:
        return not self.uuids and not self.names and not self.ids and not self.tokens

    @property
    def aliases(self) -> frozenset[tuple[str, str]]:
        return frozenset({('uuid', value) for value in self.uuids}
                         | {('name', value) for value in self.names}
                         | {('id', value) for value in self.ids}
                         | {('token', value) for value in self.tokens})

    def intersects(self, other: _OrgIdentity) -> bool:
        return bool((self.uuids & other.uuids) or (self.names & other.names)
                    or (self.ids & other.ids) or (self.tokens & other.tokens))

    def merge(self, other: _OrgIdentity) -> _OrgIdentity:
        return _OrgIdentity(self.uuids | other.uuids, self.names | other.names,
                            self.ids | other.ids, self.tokens | other.tokens)


def _get_field(value: Any, field_name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(field_name)
    return getattr(value, field_name, None)


def _normalise_uuid(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text or text in {'0', 'none', 'null'}:
        return None
    return text


def _normalise_name(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text.casefold()


def _display_name(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _token(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text.casefold() if text else None


def _normalise_org_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in {'0', 'none', 'null'}:
        return None
    try:
        identifier = int(text)
    except ValueError:
        return None
    return str(identifier) if identifier else None


def _org_identity(value: Any) -> _OrgIdentity:
    if value is None:
        return _OrgIdentity()

    if isinstance(value, (list, tuple)):
        identities = [_org_identity(entry) for entry in value]
        merged = _OrgIdentity()
        for identity in identities:
            merged = merged.merge(identity)
        return merged

    if isinstance(value, SharingGroupMember):
        return _org_identity(value.organisation)

    if isinstance(value, Mapping):
        for key in ('Organisation', 'organisation', 'org'):
            if key in value:
                identity = _org_identity(value[key])
                if not identity.is_empty:
                    return identity
                break
        uuid = _normalise_uuid(value.get('uuid'))
        name = _normalise_name(value.get('name'))
        identifier = _normalise_org_id(value.get('id', value.get('org_id')))
        tokens = frozenset(token for token in (
            _token(value.get('uuid')),
            _token(value.get('name')),
            _token(value.get('id')),
            _token(value.get('org_id')),
        ) if token is not None)
        return _OrgIdentity(
            frozenset({uuid}) if uuid else frozenset(),
            frozenset({name}) if name else frozenset(),
            frozenset({identifier}) if identifier else frozenset(),
            tokens
        )

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return _OrgIdentity()
        token = frozenset({text.casefold()})
        uuid = _normalise_uuid(text)
        if uuid and _UUID_RE.match(uuid):
            return _OrgIdentity(frozenset({uuid}), frozenset(), frozenset(), token)
        identifier = _normalise_org_id(text)
        if identifier is not None:
            return _OrgIdentity(frozenset(), frozenset(), frozenset({identifier}), token)
        name = _normalise_name(text)
        return _OrgIdentity(frozenset(), frozenset({name}) if name else frozenset(),
                            frozenset(), token)

    if isinstance(value, int) and not isinstance(value, bool):
        identifier = _normalise_org_id(value)
        return _OrgIdentity(frozenset(), frozenset(),
                            frozenset({identifier}) if identifier else frozenset(),
                            frozenset({str(value).casefold()}))

    uuid = _normalise_uuid(_get_field(value, 'uuid'))
    name = _normalise_name(_get_field(value, 'name'))
    identifier = _normalise_org_id(_get_field(value, 'id') if _get_field(value, 'id') is not None
                                   else _get_field(value, 'org_id'))
    if uuid and not _UUID_RE.match(uuid):
        uuid = None
    tokens = frozenset(token for token in (
        _token(_get_field(value, 'uuid')),
        _token(_get_field(value, 'name')),
        _token(_get_field(value, 'id')),
        _token(_get_field(value, 'org_id')),
    ) if token is not None)
    return _OrgIdentity(
        frozenset({uuid}) if uuid else frozenset(),
        frozenset({name}) if name else frozenset(),
        frozenset({identifier}) if identifier else frozenset(),
        tokens
    )


@dataclass
class _GroupSpec:
    id: str | None = None
    uuid: str | None = None
    name: str | None = None
    display_name: str | None = None
    members: list[_OrgIdentity] = field(default_factory=list)
    members_complete: bool = True
    all_orgs: bool = False
    conflicted: bool = False
    extra_aliases: set[tuple[str, str]] = field(default_factory=set)

    @property
    def aliases(self) -> frozenset[tuple[str, str]]:
        aliases = set()
        if self.id is not None:
            aliases.add(('uuid', self.id) if _UUID_RE.match(self.id) else ('id', self.id))
        if self.uuid is not None:
            aliases.add(('uuid', self.uuid))
        if self.name is not None:
            aliases.add(('name', self.name))
        aliases.update(self.extra_aliases)
        return frozenset(aliases)

    def merge(self, other: _GroupSpec) -> None:
        for field_name in ('id', 'uuid', 'name'):
            if getattr(self, field_name) is None:
                setattr(self, field_name, getattr(other, field_name))
        if self.display_name is None:
            self.display_name = other.display_name
        self.members = _merge_org_identities(self.members + other.members)
        self.members_complete = self.members_complete and other.members_complete
        self.all_orgs = self.all_orgs or other.all_orgs
        self.conflicted = self.conflicted or other.conflicted
        self.extra_aliases.update(other.extra_aliases)


def _merge_org_identities(identities: Iterable[_OrgIdentity]) -> list[_OrgIdentity]:
    merged: list[_OrgIdentity] = []
    for identity in identities:
        if identity.is_empty:
            continue
        for index, current in enumerate(merged):
            if (current.uuids & identity.uuids or current.names & identity.names
                    or current.ids & identity.ids or current.tokens & identity.tokens):
                merged[index] = current.merge(identity)
                break
        else:
            merged.append(identity)
    return merged


def _normalise_group_field(field_name: str, value: Any) -> str | None:
    if field_name == 'id':
        if value is None:
            return None
        text = str(value).strip()
        if not text or text == '0':
            return None
        try:
            return str(int(text))
        except ValueError:
            return text.lower()
    if field_name == 'uuid':
        return _normalise_uuid(value)
    return _normalise_name(value)


def _alias_for(field_name: str, value: Any) -> tuple[str, str] | None:
    normalised = _normalise_group_field(field_name, value)
    if normalised is None:
        return None
    if field_name == 'id' and _UUID_RE.match(normalised):
        return ('uuid', normalised)
    return (field_name, normalised)


def _key_as_group_fields(key: Any) -> tuple[str | None, str | None]:
    if key is None:
        return None, None
    normalised = _normalise_group_field('id', key)
    if normalised is not None and _UUID_RE.match(normalised):
        return None, normalised
    return normalised, None


def _key_alias(key: Any) -> tuple[str, str] | None:
    if key is None:
        return None
    normalised = _normalise_group_field('id', key)
    if normalised is None:
        return None
    if _UUID_RE.match(normalised):
        return ('uuid', normalised)
    return ('id', normalised)


def _normalise_spec_ids(id_value: Any, uuid_value: Any) -> tuple[str | None, str | None]:
    normalised_id = _normalise_group_field('id', id_value)
    normalised_uuid = _normalise_group_field('uuid', uuid_value)
    if normalised_id is not None and _UUID_RE.match(normalised_id) and normalised_uuid is None:
        normalised_uuid = normalised_id
        normalised_id = None
    return normalised_id, normalised_uuid


def _specs_share_alias(left: _GroupSpec, right: _GroupSpec) -> bool:
    return bool(left.aliases & right.aliases)


def _specs_compatible(left: _GroupSpec, right: _GroupSpec) -> bool:
    for field_name in ('id', 'uuid', 'name'):
        left_value = getattr(left, field_name)
        right_value = getattr(right, field_name)
        if left_value is not None and right_value is not None and left_value != right_value:
            return False
    return True


class _GroupRegistry:

    def __init__(self, specs: Iterable[_GroupSpec]) -> None:
        self.groups: list[_GroupSpec] = []
        self.alias_index: dict[tuple[str, str], _GroupSpec] = {}
        self.conflicted_aliases: set[tuple[str, str]] = set()
        self._merge_specs(specs)
        self._build_index()

    def _merge_specs(self, specs: Iterable[_GroupSpec]) -> None:
        for spec in specs:
            matches = [group for group in self.groups if _specs_share_alias(group, spec)]
            if not matches:
                self.groups.append(spec)
                continue
            compatible = all(_specs_compatible(group, spec) for group in matches)
            if compatible:
                for index, left in enumerate(matches):
                    for right in matches[index + 1:]:
                        if not _specs_compatible(left, right):
                            compatible = False
                            break
                    if not compatible:
                        break
            if not compatible:
                for group in matches:
                    group.conflicted = True
                spec.conflicted = True
                self.groups.append(spec)
                continue
            target = matches[0]
            for field_name in ('id', 'uuid', 'name'):
                if getattr(target, field_name) is None:
                    setattr(target, field_name, getattr(spec, field_name))
            target.merge(spec)
            for group in matches[1:]:
                target.merge(group)
                self.groups.remove(group)

    def _build_index(self) -> None:
        for group in self.groups:
            for alias in group.aliases:
                if group.conflicted:
                    self.conflicted_aliases.add(alias)
                    continue
                existing = self.alias_index.get(alias)
                if existing is not None and existing is not group:
                    if _specs_compatible(existing, group):
                        existing.merge(group)
                    else:
                        existing.conflicted = True
                        group.conflicted = True
                        self.conflicted_aliases.add(alias)
                    continue
                self.alias_index[alias] = group

    def resolve(self, refs: Iterable[tuple[str, str]]) -> tuple[_GroupSpec | None, str | None]:
        refs = tuple(dict.fromkeys(refs))
        if not refs:
            return None, 'missing_sharing_group_identity'
        if any(ref in self.conflicted_aliases for ref in refs):
            return None, 'sharing_group_identity_conflict'
        groups: set[int] = set()
        found: list[_GroupSpec] = []
        for ref in refs:
            group = self.alias_index.get(ref)
            if group is None:
                continue
            if group.conflicted:
                return None, 'sharing_group_identity_conflict'
            if id(group) not in groups:
                groups.add(id(group))
                found.append(group)
        if not found:
            return None, 'missing_sharing_group_membership'
        if len(found) > 1:
            return None, 'sharing_group_identity_conflict'
        return found[0], None


def _group_spec_from_value(value: Any, key: Any = None) -> _GroupSpec:
    key_id, key_uuid = _key_as_group_fields(key)
    key_alias = _key_alias(key)
    if isinstance(value, SharingGroupMembership):
        members = None if value.members is None else value.members
        value_id, value_uuid = _normalise_spec_ids(value.id, value.uuid)
        spec = _GroupSpec(
            id=value_id if value_id is not None else key_id,
            uuid=value_uuid if value_uuid is not None else key_uuid,
            name=_normalise_group_field('name', value.name),
            display_name=_display_name(value.name),
            members_complete=members is not None,
            all_orgs=value.all_orgs,
            conflicted=((key_id is not None and value_id is not None and key_id != value_id)
                        or (key_uuid is not None and value_uuid is not None and key_uuid != value_uuid))
        )
        if spec.conflicted and key_alias is not None:
            spec.extra_aliases.add(key_alias)
        if members is not None:
            spec.members, spec.members_complete = _org_identities_from_members(members)
        if value.owner is not None:
            owner = _org_identity(value.owner)
            if owner.is_empty:
                spec.members_complete = False
            else:
                spec.members = _merge_org_identities(spec.members + [owner])
        return spec

    if isinstance(value, MISPSharingGroup):
        value_id, value_uuid = _normalise_spec_ids(getattr(value, 'id', None),
                                                   getattr(value, 'uuid', None))
        spec = _GroupSpec(
            id=value_id if value_id is not None else key_id,
            uuid=value_uuid if value_uuid is not None else key_uuid,
            name=_normalise_group_field('name', getattr(value, 'name', None)),
            display_name=_display_name(getattr(value, 'name', None)),
            members_complete=True,
            conflicted=((key_id is not None and value_id is not None and key_id != value_id)
                        or (key_uuid is not None and value_uuid is not None and key_uuid != value_uuid))
        )
        if spec.conflicted and key_alias is not None:
            spec.extra_aliases.add(key_alias)
        owner_value = getattr(value, 'Organisation', None)
        owner = _org_identity(owner_value)
        if not owner.is_empty:
            spec.members = _merge_org_identities(spec.members + [owner])
        elif owner_value is not None:
            spec.members_complete = False
        members = list(getattr(value, 'SharingGroupOrg', []) or [])
        identities, complete = _org_identities_from_members(members)
        spec.members = _merge_org_identities(spec.members + identities)
        spec.members_complete = complete
        return spec

    if isinstance(value, Mapping):
        if 'SharingGroup' in value and isinstance(value['SharingGroup'], Mapping):
            nested = dict(value['SharingGroup'])
            for extra_key in ('Organisation', 'SharingGroupOrg', 'members', 'organisations',
                              'orgs', 'owner', 'all_orgs'):
                if extra_key in value and extra_key not in nested:
                    nested[extra_key] = value[extra_key]
            value = nested
        value_id, value_uuid = _normalise_spec_ids(value.get('id'), value.get('uuid'))
        spec = _GroupSpec(
            id=value_id if value_id is not None else key_id,
            uuid=value_uuid if value_uuid is not None else key_uuid,
            name=_normalise_group_field('name', value.get('name')),
            display_name=_display_name(value.get('name')),
            all_orgs=bool(value.get('all_orgs', False)),
            conflicted=((key_id is not None and value_id is not None and key_id != value_id)
                        or (key_uuid is not None and value_uuid is not None and key_uuid != value_uuid))
        )
        if spec.conflicted and key_alias is not None:
            spec.extra_aliases.add(key_alias)
        if value.get('owner') is not None:
            owner = _org_identity(value.get('owner'))
            if owner.is_empty:
                spec.members_complete = False
            else:
                spec.members = _merge_org_identities(spec.members + [owner])
        if value.get('Organisation') is not None:
            owner = _org_identity(value.get('Organisation'))
            if owner.is_empty:
                spec.members_complete = False
            else:
                spec.members = _merge_org_identities(spec.members + [owner])
        members = value.get('members')
        if members is None:
            members = value.get('organisations')
        if members is None:
            members = value.get('orgs')
        if members is None:
            members = value.get('SharingGroupOrg')
        if members is None:
            spec.members_complete = False
            return spec
        identities, complete = _org_identities_from_members(_normalise_members(members))
        spec.members = _merge_org_identities(spec.members + identities)
        spec.members_complete = complete
        return spec

    if value is None:
        return _GroupSpec(id=key_id, uuid=key_uuid, members_complete=False)

    members = _normalise_members(value)
    identities, complete = _org_identities_from_members(members)
    return _GroupSpec(
        id=key_id,
        uuid=key_uuid,
        members=identities,
        members_complete=complete
    )


def _org_identities_from_members(members: Iterable[Any]) -> tuple[list[_OrgIdentity], bool]:
    identities: list[_OrgIdentity] = []
    complete = True
    for member in members:
        if isinstance(member, MISPSharingGroupOrg):
            value = getattr(member, 'Organisation', None)
            if _org_identity(value).is_empty and getattr(member, 'org_id', None):
                value = {'org_id': member.org_id}
        elif isinstance(member, SharingGroupMember):
            value = member.organisation
        elif isinstance(member, Mapping):
            value = member
        else:
            value = member
        identity = _org_identity(value)
        if identity.is_empty:
            complete = False
        else:
            identities.append(identity)
    return _merge_org_identities(identities), complete


class RecipientContext:
    """The caller-provided, fully offline description of a recipient.

    No server lookup or sharing-group inference is performed. Missing pieces
    make affected decisions pending rather than silently widening access.
    """

    def __init__(self, organisations: Any = None, instance_relationship: Any = None,
                 sharing_groups: Any = None, *, organisation: Any = None,
                 organizations: Any = None, org: Any = None, orgs: Any = None,
                 relationship: Any = None,
                 sharing_group_members: Any = None, memberships: Any = None,
                 accepted_distributions: Any = None, distribution_levels: Any = None,
                 version: str | None = None, schema_version: str | None = None,
                 misp_version: Any = None, **kwargs: Any) -> None:
        if organisations is None:
            organisations = (organisation if organisation is not None
                             else organizations if organizations is not None
                             else org if org is not None else orgs)
        if organisations is None:
            organisations = (kwargs.pop('organisation_uuid', None)
                             or kwargs.pop('organization_uuid', None)
                             or kwargs.pop('org_uuid', None)
                             or kwargs.pop('organisation_uuids', None)
                             or kwargs.pop('organization_uuids', None))
        if instance_relationship is None:
            instance_relationship = relationship
        if instance_relationship is None:
            instance_relationship = kwargs.pop('instance', None)
        if sharing_groups is None:
            sharing_groups = (sharing_group_members if sharing_group_members is not None
                              else memberships)
        if sharing_groups is None:
            sharing_groups = (kwargs.pop('sharing_group_memberships', None)
                              or kwargs.pop('sharing_group_membership', None))
        self.organisations = _as_sequence(organisations) if organisations is not None else ()
        self.org_identities = [_org_identity(org) for org in self.organisations]
        self.org_aliases = frozenset().union(*(identity.aliases for identity in self.org_identities)) \
            if self.org_identities else frozenset()
        self.organisations_complete = bool(self.org_identities) and all(
            not identity.is_empty for identity in self.org_identities
        )

        if schema_version is not None and version is not None and str(schema_version) != str(version):
            self.version = None
            self.version_conflict = True
        else:
            selected_version = schema_version if schema_version is not None else version
            self.version = str(selected_version if selected_version is not None
                               else SUPPORTED_RECIPIENT_VERSION)
            self.version_conflict = False

        self.instance_relationship, self.relationship_valid = _normalise_relationship(instance_relationship)
        explicit_distributions = (accepted_distributions if accepted_distributions is not None
                                  else distribution_levels)
        if explicit_distributions is None:
            self.accepted_distributions_override: frozenset[int] | None = None
        else:
            try:
                values = frozenset(int(value) for value in _as_sequence(explicit_distributions))
            except (TypeError, ValueError):
                values = frozenset()
            self.accepted_distributions_override = values if values <= {1, 2, 3} else frozenset()
        self.misp_version = _parse_misp_version(misp_version)
        self.misp_version_raw = misp_version
        self.sharing_groups = sharing_groups

        specs: list[_GroupSpec] = []
        if sharing_groups is not None:
            if isinstance(sharing_groups, Mapping):
                for key, value in sharing_groups.items():
                    specs.append(_group_spec_from_value(value, key))
            else:
                for value in _as_sequence(sharing_groups):
                    specs.append(_group_spec_from_value(value))
        self.group_registry = _GroupRegistry(specs)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RecipientContext:
        if isinstance(value, RecipientContext):
            return value
        payload = dict(value)
        if 'recipient' in payload and isinstance(payload['recipient'], Mapping):
            payload = {**payload['recipient'], **{k: v for k, v in payload.items() if k != 'recipient'}}
        payload.pop('recipient', None)
        return cls(**payload)

    @property
    def version_supported(self) -> bool:
        return not self.version_conflict and self.version == SUPPORTED_RECIPIENT_VERSION

    @property
    def relationship_supported(self) -> bool:
        return self.instance_relationship is not None and self.relationship_valid

    @property
    def misp_version_supported(self) -> bool:
        if self.misp_version_raw is None:
            return True
        return self.misp_version is not None and self.misp_version >= MINIMUM_MISP_VERSION

    @property
    def analyst_data_supported(self) -> bool:
        if self.misp_version_raw is None:
            return True
        return self.misp_version is not None and self.misp_version >= MINIMUM_ANALYST_DATA_MISP_VERSION


def _normalise_relationship(value: Any) -> tuple[InstanceRelationship | None, bool]:
    if value is None:
        return None, True
    if isinstance(value, InstanceRelationship):
        return value, True
    key = str(value).strip().casefold().replace('-', '_').replace(' ', '_')
    aliases = {
        'same_instance': InstanceRelationship.SAME_INSTANCE,
        'same': InstanceRelationship.SAME_INSTANCE,
        'local': InstanceRelationship.SAME_INSTANCE,
        'local_instance': InstanceRelationship.SAME_INSTANCE,
        'local_community': InstanceRelationship.SAME_INSTANCE,
        'internal': InstanceRelationship.SAME_INSTANCE,
        'this_community': InstanceRelationship.SAME_INSTANCE,
        'this_community_only': InstanceRelationship.SAME_INSTANCE,
        'community': InstanceRelationship.SAME_INSTANCE,
        'community_only': InstanceRelationship.SAME_INSTANCE,
        'same_community': InstanceRelationship.SAME_INSTANCE,
        'same_instance_only': InstanceRelationship.SAME_INSTANCE,
        'same_server': InstanceRelationship.SAME_INSTANCE,
        'connected': InstanceRelationship.CONNECTED,
        'connected_instance': InstanceRelationship.CONNECTED,
        'connected_instances': InstanceRelationship.CONNECTED,
        'connected_community': InstanceRelationship.CONNECTED,
        'connected_communities': InstanceRelationship.CONNECTED,
        'connected_servers': InstanceRelationship.CONNECTED,
        'sync': InstanceRelationship.CONNECTED,
        'all_communities': InstanceRelationship.ALL_COMMUNITIES,
        'all': InstanceRelationship.ALL_COMMUNITIES,
        'all_community': InstanceRelationship.ALL_COMMUNITIES,
        'global': InstanceRelationship.ALL_COMMUNITIES,
    }
    relationship = aliases.get(key)
    return relationship, relationship is not None


def _parse_misp_version(value: Any) -> tuple[int, ...] | None:
    if value is None:
        return None
    if isinstance(value, (tuple, list)):
        try:
            return tuple(int(part) for part in value)
        except (TypeError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text[:1] in {'v', 'V'}:
        text = text[1:]
    match = re.match(r'^(\d+(?:\.\d+)*)', text)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split('.'))


@dataclass(frozen=True)
class _Verdict:
    decision: SharingDecision
    reason: str
    effective_distribution: int | None = None


@dataclass
class _RecordedItem:
    item: Any
    kind: str
    verdict: _Verdict


class ShareProjection:
    """The result of an offline recipient-view projection."""

    def __init__(self, event: MISPEvent | None, status: ProjectionStatus,
                 audit: Iterable[ShareAuditEntry]) -> None:
        self._event = event
        self.status = status
        self.audit = list(audit)

    @property
    def event(self) -> MISPEvent | None:
        return self._event

    @property
    def exportable(self) -> bool:
        return self._event is not None and self.status in {
            ProjectionStatus.ALLOWED, ProjectionStatus.PARTIAL
        }

    @property
    def pending(self) -> bool:
        return self.status == ProjectionStatus.PENDING

    @property
    def denied(self) -> bool:
        return self.status == ProjectionStatus.DENIED

    @property
    def allowed(self) -> bool:
        return self.status == ProjectionStatus.ALLOWED

    def to_dict(self) -> dict[str, Any] | None:
        if self._event is None:
            return None
        return {'Event': _json.loads(self._event.to_json())}

    def to_json(self, sort_keys: bool = False, indent: int | None = None) -> str | None:
        payload = self.to_dict()
        if payload is None:
            return None
        return _json.dumps(payload, sort_keys=sort_keys, indent=indent)

    def to_misp_event(self) -> MISPEvent | None:
        return self._event

    @property
    def payload(self) -> dict[str, Any] | None:
        return self.to_dict()

    def misp_json(self, sort_keys: bool = False, indent: int | None = None) -> str | None:
        return self.to_json(sort_keys=sort_keys, indent=indent)

    @property
    def audit_dicts(self) -> list[dict[str, Any]]:
        return [entry.to_dict() for entry in self.audit]

    def reason_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.audit:
            counts[entry.reason] = counts.get(entry.reason, 0) + 1
        return counts

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(status={self.status.value}, audit={len(self.audit)})>'


class _Projector:

    def __init__(self, event: MISPEvent, recipient: RecipientContext) -> None:
        self.event = event
        self.recipient = recipient
        self.audit: list[ShareAuditEntry] = []
        self.records: dict[int, _RecordedItem] = {}
        self.excluded_uuids: set[str] = set()
        self.exported_uuids: set[str] = set()
        self.extra_pending = False
        self.event_verdict: _Verdict | None = None

    def run(self) -> ShareProjection:
        if not self.recipient.version_supported:
            self._audit('event', 'unsupported_recipient_version', self.event)
            return ShareProjection(None, ProjectionStatus.PENDING, self.audit)

        if not self.recipient.misp_version_supported:
            self._audit('event', 'unsupported_misp_version', self.event)
            return ShareProjection(None, ProjectionStatus.PENDING, self.audit)

        verdict = self._evaluate_event(self.event)
        self.event_verdict = verdict
        self.records[id(self.event)] = _RecordedItem(self.event, 'event', verdict)
        if verdict.decision != SharingDecision.ALLOW:
            self._audit('event', verdict.reason, self.event)
            status = (ProjectionStatus.DENIED if verdict.decision == SharingDecision.DENY
                      else ProjectionStatus.PENDING)
            return ShareProjection(None, status, self.audit)

        self._evaluate_children()
        self._prune_event()
        self._collect_exported_uuids()
        self._filter_derived_content()
        self._sanitise_event()
        return ShareProjection(self.event, self._status(), self.audit)

    def _status(self) -> ProjectionStatus:
        decisions = [record.verdict.decision for key, record in self.records.items()
                     if key != id(self.event)]
        if self.extra_pending or any(decision == SharingDecision.PENDING for decision in decisions):
            return ProjectionStatus.PENDING
        if any(decision == SharingDecision.DENY for decision in decisions):
            return ProjectionStatus.PARTIAL
        return ProjectionStatus.ALLOWED

    def _evaluate_event(self, event: MISPEvent) -> _Verdict:
        if _distribution_invalid(event):
            return _Verdict(SharingDecision.PENDING, 'unsupported_distribution')
        distribution = _distribution_value(event)
        if distribution is None:
            return _Verdict(SharingDecision.PENDING, 'missing_distribution')
        if distribution == Distribution.inherit.value:
            return _Verdict(SharingDecision.PENDING, 'inherit_without_parent')
        return self._evaluate_explicit(distribution, event, event)

    def _evaluate_child(self, item: Any, parent: _Verdict, kind: str) -> _Verdict:
        if parent.decision != SharingDecision.ALLOW:
            return _Verdict(SharingDecision.DENY, 'parent_not_shared')

        if kind in {'note', 'opinion', 'relationship'} and not self.recipient.analyst_data_supported:
            return _Verdict(SharingDecision.PENDING, 'unsupported_misp_version')

        if kind in {'note', 'opinion', 'relationship'}:
            default_distribution = 1
        else:
            default_distribution = Distribution.inherit.value

        if _distribution_invalid(item):
            return _Verdict(SharingDecision.PENDING, 'unsupported_distribution')
        distribution = _distribution_value(item)
        if distribution is None:
            distribution = default_distribution

        if distribution == Distribution.inherit.value:
            return _Verdict(SharingDecision.ALLOW, 'inherited', parent.effective_distribution)
        return self._evaluate_explicit(distribution, item, self.event)

    def _evaluate_explicit(self, distribution: int, item: Any, event: MISPEvent) -> _Verdict:
        if distribution == Distribution.your_organisation_only.value:
            owner = _org_identity(_get_field(item, 'Orgc') or _get_field(event, 'Orgc'))
            if owner.is_empty:
                return _Verdict(SharingDecision.PENDING, 'missing_owner_organisation', distribution)
            if not self._has_recipient():
                return _Verdict(SharingDecision.PENDING, 'missing_recipient_organisations', distribution)
            if self.recipient.org_aliases & owner.aliases:
                return _Verdict(SharingDecision.ALLOW, 'owner', distribution)
            return _Verdict(SharingDecision.DENY, 'recipient_not_event_owner', distribution)

        if distribution in {
            Distribution.this_community_only.value,
            Distribution.connected_communities.value,
            Distribution.all_communities.value
        }:
            if not self._has_recipient():
                return _Verdict(SharingDecision.PENDING, 'missing_recipient_organisations', distribution)
            relationship = self.recipient.instance_relationship
            if self.recipient.accepted_distributions_override is not None:
                if distribution in self.recipient.accepted_distributions_override:
                    return _Verdict(SharingDecision.ALLOW, 'distribution_visible', distribution)
                return _Verdict(SharingDecision.DENY, 'distribution_not_visible_to_recipient', distribution)
            if relationship is None:
                if self.recipient.relationship_valid:
                    return _Verdict(SharingDecision.PENDING, 'missing_instance_relationship', distribution)
                return _Verdict(SharingDecision.PENDING, 'unsupported_instance_relationship', distribution)
            if distribution in relationship.accepted_distributions:
                return _Verdict(SharingDecision.ALLOW, 'distribution_visible', distribution)
            return _Verdict(SharingDecision.DENY, 'distribution_not_visible_to_recipient', distribution)

        if distribution == Distribution.sharing_group.value:
            if not self._has_recipient():
                return _Verdict(SharingDecision.PENDING, 'missing_recipient_organisations', distribution)
            group, reason = self._resolve_sharing_group(item)
            if reason is not None or group is None:
                return _Verdict(SharingDecision.PENDING, reason or 'missing_sharing_group_membership', distribution)
            if group.all_orgs:
                return _Verdict(SharingDecision.ALLOW, 'sharing_group_all_orgs', distribution)
            if any(member.intersects(identity)
                   for member in group.members for identity in self.recipient.org_identities):
                return _Verdict(SharingDecision.ALLOW, 'sharing_group_member', distribution)
            if not group.members_complete:
                return _Verdict(SharingDecision.PENDING, 'incomplete_sharing_group_membership', distribution)
            return _Verdict(SharingDecision.DENY, 'recipient_not_in_sharing_group', distribution)

        return _Verdict(SharingDecision.PENDING, 'unsupported_distribution', distribution)

    def _has_recipient(self) -> bool:
        return self.recipient.organisations_complete

    def _resolve_sharing_group(self, item: Any) -> tuple[_GroupSpec | None, str | None]:
        primary: list[tuple[str, str]] = []
        embedded: list[tuple[str, str]] = []
        sharing_group_id = _get_field(item, 'sharing_group_id')
        alias = _alias_for('id', sharing_group_id)
        if alias is not None:
            primary.append(alias)
        sharing_group_uuid = _get_field(item, 'sharing_group_uuid')
        alias = _alias_for('uuid', sharing_group_uuid)
        if alias is not None:
            embedded.append(alias)
        sharing_group = _get_field(item, 'SharingGroup')
        if sharing_group is not None:
            if isinstance(sharing_group, Mapping) and 'SharingGroup' in sharing_group:
                sharing_group = sharing_group['SharingGroup']
            for field_name in ('id', 'uuid', 'name'):
                alias = _alias_for(field_name, _get_field(sharing_group, field_name))
                if alias is not None:
                    embedded.append(alias)

        lookup = primary + embedded
        group, reason = self.recipient.group_registry.resolve(lookup)
        if group is None:
            return None, reason

        for field_name in ('id', 'uuid', 'name'):
            embedded_value = _get_field(sharing_group, field_name) if sharing_group is not None else None
            known_value = getattr(group, field_name)
            if embedded_value is None or known_value is None:
                continue
            normalised = _normalise_group_field(field_name, embedded_value)
            if normalised is not None and normalised != known_value:
                return None, 'sharing_group_identity_conflict'
        return group, None

    def _evaluate_children(self) -> None:
        event_verdict = self.event_verdict
        if event_verdict is None:
            return
        self._evaluate_attributes(_as_list(self.event.Attribute), event_verdict, 'attribute')
        for obj in _as_list(self.event.Object):
            verdict = self._record(obj, 'object', self._evaluate_child(obj, event_verdict, 'object'))
            if verdict.decision == SharingDecision.ALLOW:
                self._evaluate_attributes(_as_list(obj.Attribute), verdict, 'object_attribute')
                self._evaluate_analyst_data(obj, verdict)
                self._evaluate_object_derived(obj)
        for report in _as_list(self.event.EventReport):
            verdict = self._record(report, 'event_report',
                                   self._evaluate_child(report, event_verdict, 'event_report'))
            if verdict.decision == SharingDecision.ALLOW:
                self._evaluate_analyst_data(report, verdict)
        self._evaluate_analyst_data(self.event, event_verdict)

    def _evaluate_attributes(self, attributes: Iterable[MISPAttribute], parent: _Verdict,
                             kind: str) -> None:
        for attribute in attributes:
            verdict = self._record(attribute, kind, self._evaluate_child(attribute, parent, kind))
            if verdict.decision == SharingDecision.ALLOW:
                self._evaluate_analyst_data(attribute, verdict)

    def _evaluate_analyst_data(self, container: Any, parent: _Verdict,
                               ancestors: set[int] | None = None) -> None:
        if ancestors is None:
            ancestors = set()
        if id(container) in ancestors:
            return
        ancestors = ancestors | {id(container)}
        for note in _as_list(getattr(container, 'Note', None)):
            verdict = self._record(note, 'note', self._evaluate_child(note, parent, 'note'))
            if verdict.decision == SharingDecision.ALLOW:
                self._evaluate_analyst_data(note, verdict, ancestors)
        for opinion in _as_list(getattr(container, 'Opinion', None)):
            verdict = self._record(opinion, 'opinion', self._evaluate_child(opinion, parent, 'opinion'))
            if verdict.decision == SharingDecision.ALLOW:
                self._evaluate_analyst_data(opinion, verdict, ancestors)
        for relationship in _as_list(getattr(container, 'Relationship', None)):
            self._record(relationship, 'relationship',
                         self._evaluate_child(relationship, parent, 'relationship'))

    def _evaluate_object_derived(self, obj: MISPObject) -> None:
        for reference in _as_list(getattr(obj, 'ObjectReference', None)):
            self.records[id(reference)] = _RecordedItem(
                reference, 'object_reference',
                _Verdict(SharingDecision.ALLOW, 'object_reference_pending_filter')
            )

    def _record(self, item: Any, kind: str, verdict: _Verdict) -> _Verdict:
        self.records[id(item)] = _RecordedItem(item, kind, verdict)
        if verdict.decision != SharingDecision.ALLOW:
            self._audit(kind, verdict.reason, item)
            uuid = _normalise_uuid(_get_field(item, 'uuid'))
            if uuid:
                self.excluded_uuids.add(uuid)
        return verdict

    def _audit(self, kind: str, reason: str, item: Any) -> None:
        uuid = _normalise_uuid(_get_field(item, 'uuid'))
        identifier = _get_field(item, 'id')
        sharing_group_id = _normalise_group_field('id', _get_field(item, 'sharing_group_id'))
        self.audit.append(ShareAuditEntry(
            kind=kind,
            reason=reason,
            uuid=uuid,
            id=None if identifier is None else str(identifier),
            sharing_group_id=sharing_group_id
        ))

    def _allowed(self, item: Any) -> bool:
        record = self.records.get(id(item))
        return record is not None and record.verdict.decision == SharingDecision.ALLOW

    def _prune_event(self) -> None:
        event = self.event
        kept_attributes = []
        for attribute in _as_list(event.Attribute):
            if self._allowed(attribute):
                kept_attributes.append(attribute)
                self._prune_analyst_data(attribute)
            else:
                self._collect_excluded_subtree(attribute)
        event.Attribute = kept_attributes

        kept_objects = []
        for obj in _as_list(event.Object):
            if not self._allowed(obj):
                self._collect_excluded_subtree(obj)
                continue
            kept_object_attributes = []
            for attribute in _as_list(obj.Attribute):
                if self._allowed(attribute):
                    kept_object_attributes.append(attribute)
                    self._prune_analyst_data(attribute)
                else:
                    self._collect_excluded_subtree(attribute)
            obj.Attribute = kept_object_attributes
            self._reset_object_attribute_cache(obj)
            self._prune_analyst_data(obj)
            kept_objects.append(obj)
        event.Object = kept_objects

        kept_reports = []
        for report in _as_list(event.EventReport):
            if self._allowed(report):
                kept_reports.append(report)
                self._prune_analyst_data(report)
            else:
                self._collect_excluded_subtree(report)
        event.EventReport = kept_reports

        self._prune_analyst_data(event)

    def _prune_analyst_data(self, container: Any, ancestors: set[int] | None = None) -> None:
        if ancestors is None:
            ancestors = set()
        if id(container) in ancestors:
            return
        ancestors = ancestors | {id(container)}
        for list_name in ('Note', 'Opinion', 'Relationship'):
            values = getattr(container, list_name, None)
            if values is None:
                continue
            kept = []
            for value in _as_list(values):
                if id(value) in ancestors:
                    self._audit('analyst_data', 'analyst_data_cycle', value)
                    continue
                if self._allowed(value):
                    if list_name in {'Note', 'Opinion'}:
                        self._prune_analyst_data(value, ancestors)
                    kept.append(value)
                else:
                    self._collect_excluded_subtree(value)
            setattr(container, list_name, kept)

    def _collect_excluded_subtree(self, item: Any, seen: set[int] | None = None) -> None:
        if seen is None:
            seen = set()
        if id(item) in seen:
            return
        seen.add(id(item))
        uuid = _normalise_uuid(_get_field(item, 'uuid'))
        if uuid:
            self.excluded_uuids.add(uuid)
        if isinstance(item, MISPObject):
            for attribute in item.Attribute:
                self._collect_excluded_subtree(attribute, seen)
            for reference in getattr(item, 'ObjectReference', []) or []:
                reference_uuid = _normalise_uuid(_get_field(reference, 'uuid'))
                if reference_uuid:
                    self.excluded_uuids.add(reference_uuid)
        for list_name in ('Note', 'Opinion', 'Relationship'):
            values = getattr(item, list_name, None)
            for value in _as_list(values):
                self._collect_excluded_subtree(value, seen)

    def _reset_object_attribute_cache(self, obj: MISPObject) -> None:
        cache: dict[str, list[MISPAttribute]] = defaultdict(list)
        for attribute in obj.Attribute:
            relation = getattr(attribute, 'object_relation', None)
            if relation is not None:
                cache[relation].append(attribute)
        obj.__dict__['_MISPObject__fast_attribute_access'] = cache

    def _collect_exported_uuids(self) -> None:
        self._add_exported(self.event)
        self._add_galaxy_uuids(self.event)
        for attribute in _as_list(self.event.Attribute):
            self._add_exported(attribute)
            self._add_galaxy_uuids(attribute)
            self._add_analyst_uuids(attribute)
        for obj in _as_list(self.event.Object):
            self._add_exported(obj)
            self._add_galaxy_uuids(obj)
            for attribute in _as_list(obj.Attribute):
                self._add_exported(attribute)
                self._add_galaxy_uuids(attribute)
                self._add_analyst_uuids(attribute)
            self._add_analyst_uuids(obj)
        for report in _as_list(self.event.EventReport):
            self._add_exported(report)
            self._add_analyst_uuids(report)
        self._add_analyst_uuids(self.event)

    def _add_exported(self, item: Any) -> None:
        uuid = _normalise_uuid(_get_field(item, 'uuid'))
        if uuid:
            self.exported_uuids.add(uuid)

    def _add_galaxy_uuids(self, container: Any) -> None:
        galaxies = getattr(container, 'Galaxy', None)
        for galaxy in _as_list(galaxies):
            self._add_exported(galaxy)
            for cluster in _as_list(getattr(galaxy, 'GalaxyCluster', None)):
                self._add_exported(cluster)

    def _add_analyst_uuids(self, container: Any, seen: set[int] | None = None) -> None:
        if seen is None:
            seen = set()
        if id(container) in seen:
            return
        seen.add(id(container))
        for list_name in ('Note', 'Opinion', 'Relationship'):
            values = getattr(container, list_name, None)
            if values is None:
                continue
            for value in _as_list(values):
                self._add_exported(value)
                if list_name in {'Note', 'Opinion'}:
                    self._add_analyst_uuids(value, seen)

    def _filter_derived_content(self) -> None:
        self._drop_shadow_attributes(self.event)
        self._filter_event_sightings(self.event)
        for attribute in self._all_attributes():
            self._drop_shadow_attributes(attribute)
            self._drop_search_context(attribute, 'attribute')
            self._filter_sightings(attribute)
            self._filter_related_attributes(attribute)
        for obj in _as_list(self.event.Object):
            self._drop_search_context(obj, 'object')
            self._filter_object_references(obj)
        for report in _as_list(self.event.EventReport):
            self._drop_search_context(report, 'event_report')
        for container in self._all_analyst_containers():
            if container is self.event:
                continue
            self._drop_search_context(container, 'analyst_data')
        self._drop_related_events(self.event)
        self._filter_cryptographic_keys(self.event)
        self._filter_analyst_targets()

    def _filter_event_sightings(self, event: MISPEvent) -> None:
        values = getattr(event, 'Sighting', None)
        if values is None:
            return
        if not isinstance(values, list):
            values = [values]
        kept = []
        for sighting in values:
            target_uuid = _normalise_uuid(_get_field(sighting, 'attribute_uuid'))
            if target_uuid is not None and target_uuid in self.exported_uuids:
                kept.append(sighting)
            else:
                reason = ('sighting_attribute_excluded' if target_uuid is not None
                          else 'sighting_attribute_missing')
                self._audit('sighting', reason, sighting)
        event.Sighting = kept

    def _all_attributes(self) -> list[MISPAttribute]:
        attributes = list(_as_list(self.event.Attribute))
        for obj in _as_list(self.event.Object):
            attributes.extend(_as_list(obj.Attribute))
        return attributes

    def _drop_shadow_attributes(self, container: Any) -> None:
        values = getattr(container, 'ShadowAttribute', None)
        if values is None:
            return
        if not isinstance(values, list):
            self._audit('shadow_attribute', 'shadow_attribute_not_projected', values)
            setattr(container, 'ShadowAttribute', [])
            return
        for value in values:
            self._audit('shadow_attribute', 'shadow_attribute_not_projected', value)
        setattr(container, 'ShadowAttribute', [])

    def _drop_search_context(self, item: Any, kind: str) -> None:
        if not hasattr(item, 'Event'):
            return
        event = getattr(item, 'Event')
        if event is None:
            return
        self._audit(kind, 'search_context_not_projected', item)
        try:
            delattr(item, 'Event')
        except AttributeError:
            pass

    def _filter_sightings(self, attribute: MISPAttribute) -> None:
        values = getattr(attribute, 'Sighting', None)
        if values is None:
            return
        if not isinstance(values, list):
            values = [values]
        kept = []
        for sighting in values:
            target_uuid = _normalise_uuid(_get_field(sighting, 'attribute_uuid'))
            if target_uuid is None or target_uuid == _normalise_uuid(getattr(attribute, 'uuid', None)):
                kept.append(sighting)
            elif target_uuid in self.exported_uuids:
                kept.append(sighting)
            else:
                self._audit('sighting', 'sighting_attribute_excluded', sighting)
        attribute.Sighting = kept

    def _filter_related_attributes(self, attribute: MISPAttribute) -> None:
        values = getattr(attribute, 'RelatedAttribute', None)
        if values is None:
            return
        if not isinstance(values, list):
            values = [values]
        for related in values:
            self._audit('related_attribute', 'related_attribute_not_projected', related)
        attribute.RelatedAttribute = []

    def _filter_object_references(self, obj: MISPObject) -> None:
        kept = []
        values = getattr(obj, 'ObjectReference', None)
        if values is None:
            return
        if not isinstance(values, list):
            values = [values]
        for reference in values:
            object_uuid = _normalise_uuid(_get_field(reference, 'object_uuid'))
            referenced_uuid = _normalise_uuid(_get_field(reference, 'referenced_uuid'))
            if object_uuid is None or referenced_uuid is None:
                self._audit('object_reference', 'object_reference_missing_endpoint', reference)
                continue
            if object_uuid != _normalise_uuid(getattr(obj, 'uuid', None)):
                self._audit('object_reference', 'object_reference_wrong_source', reference)
                continue
            if referenced_uuid in self.exported_uuids:
                kept.append(reference)
            elif referenced_uuid in self.excluded_uuids:
                self._audit('object_reference', 'referenced_object_excluded', reference)
            else:
                self._audit('object_reference', 'referenced_object_not_exported', reference)
        obj.ObjectReference = kept

    def _drop_related_events(self, event: MISPEvent) -> None:
        related = getattr(event, 'RelatedEvent', None)
        if related is None:
            return
        if not isinstance(related, list):
            related = [related]
        for entry in related:
            related_event = entry.get('Event') if isinstance(entry, Mapping) else entry
            self._audit('related_event', 'related_event_not_projected', related_event)
        event.RelatedEvent = []

    def _filter_cryptographic_keys(self, event: MISPEvent) -> None:
        values = getattr(event, 'CryptographicKey', None)
        if values is None:
            return
        if not isinstance(values, list):
            values = [values]
        kept = []
        for key in values:
            parent_uuid = _normalise_uuid(_get_field(key, 'parent_uuid'))
            parent_type = _get_field(key, 'parent_type')
            if parent_uuid is None:
                if parent_type in (None, 'Event'):
                    kept.append(key)
                else:
                    self._audit('cryptographic_key', 'cryptographic_key_parent_missing', key)
                    self.extra_pending = True
                continue
            if parent_uuid in self.exported_uuids:
                kept.append(key)
            elif parent_uuid in self.excluded_uuids:
                self._audit('cryptographic_key', 'cryptographic_key_parent_excluded', key)
            else:
                self._audit('cryptographic_key', 'cryptographic_key_parent_not_exported', key)
                self.extra_pending = True
        event.CryptographicKey = kept

    def _filter_analyst_targets(self) -> None:
        containers = self._all_analyst_containers()
        for container in containers:
            for list_name, kind in (('Note', 'note'), ('Opinion', 'opinion')):
                values = getattr(container, list_name, None)
                if values is None:
                    continue
                kept = []
                for value in _as_list(values):
                    if not self._allowed(value):
                        continue
                    if not self._analyst_target_exportable(value, kind):
                        self._unexport_subtree(value)
                        continue
                    kept.append(value)
                setattr(container, list_name, kept)
        for container in containers:
            values = getattr(container, 'Relationship', None)
            if values is None:
                continue
            kept = []
            for relationship in _as_list(values):
                if not self._allowed(relationship):
                    continue
                if not self._analyst_target_exportable(relationship, 'relationship', 'source'):
                    self._unexport_subtree(relationship)
                    continue
                if not self._analyst_relationship_target_exportable(relationship):
                    self._unexport_subtree(relationship)
                    continue
                kept.append(relationship)
            setattr(container, 'Relationship', kept)

    def _unexport_subtree(self, item: Any) -> None:
        uuid = _normalise_uuid(_get_field(item, 'uuid'))
        if uuid:
            self.exported_uuids.discard(uuid)
            self.excluded_uuids.add(uuid)
        for list_name in ('Note', 'Opinion', 'Relationship'):
            values = getattr(item, list_name, None)
            for value in _as_list(values):
                self._unexport_subtree(value)

    def _all_analyst_containers(self) -> list[Any]:
        containers: list[Any] = [self.event]
        containers.extend(_as_list(self.event.Attribute))
        containers.extend(_as_list(self.event.Object))
        for obj in _as_list(self.event.Object):
            containers.extend(_as_list(obj.Attribute))
        containers.extend(_as_list(self.event.EventReport))
        result = list(containers)
        seen = {id(container) for container in result}
        index = 0
        while index < len(result):
            container = result[index]
            index += 1
            for list_name in ('Note', 'Opinion'):
                values = getattr(container, list_name, None)
                if values is None:
                    continue
                for value in _as_list(values):
                    if id(value) not in seen:
                        seen.add(id(value))
                        result.append(value)
        return result

    def _analyst_target_exportable(self, item: Any, kind: str, label: str = 'target') -> bool:
        target_type = _get_field(item, 'object_type')
        if target_type == 'AttributeValue':
            return True
        target_uuid = _normalise_uuid(_get_field(item, 'object_uuid'))
        if target_uuid is None:
            self._audit(kind, f'{kind}_{label}_missing', item)
            self.extra_pending = True
            return False
        if target_uuid in self.exported_uuids:
            return True
        if target_uuid in self.excluded_uuids:
            self._audit(kind, f'{kind}_{label}_excluded', item)
            return False
        self._audit(kind, f'{kind}_{label}_not_exported', item)
        self.extra_pending = True
        return False

    def _analyst_relationship_target_exportable(self, relationship: MISPRelationship) -> bool:
        related_type = _get_field(relationship, 'related_object_type')
        if related_type == 'AttributeValue':
            return True
        related_uuid = _normalise_uuid(_get_field(relationship, 'related_object_uuid'))
        if related_uuid is None:
            self._audit('relationship', 'relationship_target_missing', relationship)
            self.extra_pending = True
            return False
        if related_uuid in self.exported_uuids:
            return True
        if related_uuid in self.excluded_uuids:
            self._audit('relationship', 'relationship_target_excluded', relationship)
            return False
        self._audit('relationship', 'relationship_target_not_exported', relationship)
        self.extra_pending = True
        return False

    def _sanitise_event(self) -> None:
        event = self.event
        self._sanitise_sharing_group_fields(event)
        for attribute in self._all_attributes():
            self._sanitise_sharing_group_fields(attribute, Distribution.inherit.value)
        for obj in _as_list(event.Object):
            self._sanitise_sharing_group_fields(obj, Distribution.inherit.value)
        for report in _as_list(event.EventReport):
            self._sanitise_sharing_group_fields(report, Distribution.inherit.value)
        for container in self._all_analyst_containers():
            if container is event:
                continue
            self._sanitise_sharing_group_fields(container, 1)

        attribute_count = (len(_as_list(event.Attribute))
                           + sum(len(_as_list(obj.Attribute)) for obj in _as_list(event.Object)))
        if hasattr(event, 'attribute_count'):
            event.attribute_count = str(attribute_count)
        if hasattr(event, 'object_count'):
            event.object_count = str(len(_as_list(event.Object)))
        if hasattr(event, 'sighting_timestamp'):
            delattr(event, 'sighting_timestamp')
        _force_timestamps(event)

    def _sanitise_sharing_group_fields(self, item: Any, default_distribution: int | None = None) -> None:
        distribution = _distribution_value(item)
        if distribution is None:
            distribution = default_distribution
        if distribution is None:
            return
        if distribution == Distribution.sharing_group.value:
            embedded_group = _get_field(item, 'SharingGroup')
            if isinstance(embedded_group, Mapping) and 'SharingGroup' in embedded_group:
                embedded_group = embedded_group['SharingGroup']
            group, _ = self._resolve_sharing_group(item)
            sharing_group_id = _get_field(item, 'sharing_group_id')
            needs_numeric_id = sharing_group_id in (None, 0, '0')
            if not needs_numeric_id:
                try:
                    int(sharing_group_id)
                except (TypeError, ValueError):
                    needs_numeric_id = True
            if group is None:
                if hasattr(item, 'SharingGroup'):
                    try:
                        delattr(item, 'SharingGroup')
                    except AttributeError:
                        pass
                return
            if needs_numeric_id:
                try:
                    numeric_id = int(group.id) if group.id is not None else self._synthetic_group_id(group)
                except ValueError:
                    numeric_id = self._synthetic_group_id(group)
                item.sharing_group_id = numeric_id
            else:
                numeric_id = int(sharing_group_id)
            sanitised = MISPSharingGroup()
            sanitised.id = numeric_id
            uuid = group.uuid or _normalise_uuid(_get_field(embedded_group, 'uuid'))
            name = (group.display_name or group.name
                    or _display_name(_get_field(embedded_group, 'name')))
            if uuid is not None:
                sanitised.uuid = uuid
            if name is not None:
                sanitised.name = name
            item.SharingGroup = sanitised
            return
        if hasattr(item, 'SharingGroup'):
            try:
                delattr(item, 'SharingGroup')
            except AttributeError:
                pass
        if _get_field(item, 'sharing_group_id') not in (None, 0, '0'):
            try:
                item.sharing_group_id = 0
            except AttributeError:
                pass

    def _synthetic_group_id(self, group: _GroupSpec) -> int:
        seed = group.uuid or group.name or group.id or 'sharing-group'
        value = int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16) & 0x7fffffff
        return value or 1


def _distribution_value(item: Any) -> int | None:
    value = _get_field(item, 'distribution')
    if value is None:
        return None
    if isinstance(value, Distribution):
        return int(value.value)
    if isinstance(value, bool):
        return None
    try:
        distribution = int(value)
    except (TypeError, ValueError):
        return None
    if distribution not in {0, 1, 2, 3, 4, 5}:
        return None
    return distribution


def _distribution_invalid(item: Any) -> bool:
    value = _get_field(item, 'distribution')
    if value is None:
        return False
    if isinstance(value, Distribution):
        return False
    if isinstance(value, bool):
        return True
    try:
        distribution = int(value)
    except (TypeError, ValueError):
        return True
    return distribution not in {0, 1, 2, 3, 4, 5}


def _force_timestamps(item: Any, seen: set[int] | None = None) -> None:
    if seen is None:
        seen = set()
    if not isinstance(item, AbstractMISP) or id(item) in seen:
        return
    seen.add(id(item))
    item.force_timestamp = True
    for value in item.values():
        if isinstance(value, AbstractMISP):
            _force_timestamps(value, seen)
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, AbstractMISP):
                    _force_timestamps(entry, seen)


def project_event_for_recipient(event: MISPEvent, recipient: RecipientContext | Mapping[str, Any], *,
                                copy_event: bool = True) -> ShareProjection:
    """Create an offline recipient-view projection of a MISP event.

    The source event and the caller's recipient description are never mutated.
    No network access is performed. ``copy_event`` exists only for API
    compatibility; a deep copy is always used.
    """

    if isinstance(event, MISPEvent):
        pass
    elif isinstance(event, (str, bytes)):
        loaded = MISPEvent()
        loaded.load(event)
        event = loaded
    elif isinstance(event, Mapping):
        loaded = MISPEvent()
        loaded.load(dict(event))
        event = loaded
    if not isinstance(event, MISPEvent):
        raise PyMISPError('The event to project must be a MISPEvent or a MISP JSON mapping/string.')
    if isinstance(recipient, Mapping):
        recipient = RecipientContext.from_dict(recipient)
    if not isinstance(recipient, RecipientContext):
        raise PyMISPError('The recipient must be a RecipientContext or a mapping.')

    projected_event = copy.deepcopy(event)
    return _Projector(projected_event, recipient).run()


def project_for_recipient(event: MISPEvent, recipient: RecipientContext | Mapping[str, Any], **kwargs: Any) -> ShareProjection:
    return project_event_for_recipient(event, recipient, **kwargs)


def share_projection(event: MISPEvent, recipient: RecipientContext | Mapping[str, Any], **kwargs: Any) -> ShareProjection:
    return project_event_for_recipient(event, recipient, **kwargs)


def sharing_projection(event: MISPEvent, recipient: RecipientContext | Mapping[str, Any], **kwargs: Any) -> ShareProjection:
    return project_event_for_recipient(event, recipient, **kwargs)


def offline_share_projection(event: MISPEvent, recipient: RecipientContext | Mapping[str, Any], **kwargs: Any) -> ShareProjection:
    return project_event_for_recipient(event, recipient, **kwargs)


def project_event(event: MISPEvent, recipient: RecipientContext | Mapping[str, Any], **kwargs: Any) -> ShareProjection:
    return project_event_for_recipient(event, recipient, **kwargs)


def recipient_view(event: MISPEvent, recipient: RecipientContext | Mapping[str, Any], **kwargs: Any) -> ShareProjection:
    return project_event_for_recipient(event, recipient, **kwargs)
