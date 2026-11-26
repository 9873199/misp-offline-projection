#!/usr/bin/env python

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from uuid import uuid4

from pymisp import (InstanceRelationship, MISPEvent, MISPObject, MISPOrganisation,
                    MISPSharingGroup, ProjectionStatus, RecipientContext,
                    ShareProjection)


ORG_A_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
SG_1_UUID = '11111111-1111-4111-8111-111111111111'
SG_2_UUID = '22222222-2222-4222-8222-222222222222'


def organisation(name: str, uuid: str) -> MISPOrganisation:
    org = MISPOrganisation()
    org.from_dict(name=name, uuid=uuid)
    return org


def new_event(distribution: int, *, owner: MISPOrganisation | None = None,
              sharing_group_id: int | None = None) -> MISPEvent:
    event = MISPEvent()
    event.info = 'Offline sharing projection test'
    event.distribution = distribution
    event.Orgc = owner or organisation('Organisation A', ORG_A_UUID)
    if sharing_group_id is not None:
        event.sharing_group_id = sharing_group_id
    return event


def add_object(event: MISPEvent, *, distribution: int, sharing_group_id: int | None = None,
               name: str = 'file') -> MISPObject:
    obj = MISPObject(name)
    obj.distribution = distribution
    if sharing_group_id is not None:
        obj.sharing_group_id = sharing_group_id
    event.add_object(obj)
    return obj


def add_object_attribute(obj: MISPObject, value: str, distribution: int = 5,
                         *, sharing_group_id: int | None = None) -> object:
    attribute = obj.add_attribute(
        'filename', value=value, type='filename', category='Payload delivery',
        distribution=distribution,
        **({'sharing_group_id': sharing_group_id} if sharing_group_id is not None else {})
    )
    return attribute


class TestSharingProjection(unittest.TestCase):

    def setUp(self) -> None:
        self.maxDiff = None

    def recipient(self, organisations: list[str] | None = None,
                  relationship: InstanceRelationship | str = InstanceRelationship.SAME_INSTANCE,
                  sharing_groups: dict | None = None,
                  **kwargs) -> RecipientContext:
        return RecipientContext(
            organisations=organisations or ['Organisation A'],
            instance_relationship=relationship,
            sharing_groups=sharing_groups,
            **kwargs
        )

    def test_multilevel_inheritance_and_analyst_data(self) -> None:
        event = new_event(1)
        top = event.add_attribute('filename', 'top.exe', distribution=5)
        top.add_note(note='event-visible note', distribution=5)
        top.add_opinion(opinion=70, comment='event-visible opinion', distribution=1)

        obj = add_object(event, distribution=5)
        object_attribute = add_object_attribute(obj, 'object.exe', 5)
        object_attribute.add_note(note='object-visible note', distribution=5)

        report = event.add_event_report('Report', 'Report body')
        report.add_note(note='report note', distribution=5)

        projection = event.project_for_recipient(self.recipient())

        self.assertEqual(projection.status, ProjectionStatus.ALLOWED)
        self.assertTrue(projection.exportable)
        self.assertEqual(projection.audit, [])
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        self.assertEqual(len(payload['Event']['Attribute']), 1)
        self.assertEqual(len(payload['Event']['Object']), 1)
        self.assertEqual(len(payload['Event']['Object'][0]['Attribute']), 1)
        self.assertEqual(len(payload['Event']['EventReport']), 1)
        self.assertEqual(payload['Event']['Attribute'][0]['Note'][0]['note'], 'event-visible note')
        self.assertEqual(payload['Event']['Attribute'][0]['Opinion'][0]['opinion'], '70')

    def test_disjoint_sharing_groups_are_not_merged_or_numerically_compared(self) -> None:
        event = new_event(4, sharing_group_id=1)
        event.add_attribute('filename', 'top.exe', distribution=5)

        allowed_object = add_object(event, distribution=4, sharing_group_id=1)
        add_object_attribute(allowed_object, 'allowed.exe', 5)

        denied_object = add_object(event, distribution=4, sharing_group_id=2)
        add_object_attribute(denied_object, 'denied.exe', 5)
        # Even an explicitly broader/other SG attribute cannot escape an excluded object.
        add_object_attribute(denied_object, 'denied-explicit.exe', 4, sharing_group_id=1)

        other_object = add_object(event, distribution=4, sharing_group_id=1)
        add_object_attribute(other_object, 'other-denied.exe', 4, sharing_group_id=2)

        projection = event.project_for_recipient(self.recipient(
            sharing_groups={
                1: {'uuid': SG_1_UUID, 'members': ['Organisation A']},
                2: {'uuid': SG_2_UUID, 'members': ['Organisation B']},
            }
        ))

        self.assertEqual(projection.status, ProjectionStatus.PARTIAL)
        self.assertTrue(projection.exportable)
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        object_uuids = {obj['uuid'] for obj in payload['Event']['Object']}
        self.assertIn(allowed_object.uuid, object_uuids)
        self.assertIn(other_object.uuid, object_uuids)
        self.assertNotIn(denied_object.uuid, object_uuids)
        self.assertEqual(
            [attribute['uuid'] for attribute in payload['Event']['Object'][0]['Attribute']],
            [allowed_object.attributes[0].uuid]
        )
        self.assertEqual(
            [attribute['uuid'] for attribute in payload['Event']['Object'][1].get('Attribute', [])],
            []
        )
        reasons = projection.reason_counts()
        self.assertEqual(reasons['recipient_not_in_sharing_group'], 2)

    def test_sharing_group_is_not_treated_as_a_numeric_distribution(self) -> None:
        event = new_event(3)
        obj = add_object(event, distribution=4, sharing_group_id=2)
        add_object_attribute(obj, 'hidden-by-sg.exe', 5)

        projection = event.project_for_recipient(self.recipient(
            relationship=InstanceRelationship.CONNECTED,
            sharing_groups={2: {'uuid': SG_2_UUID, 'members': ['Organisation B']}}
        ))

        self.assertEqual(projection.status, ProjectionStatus.PARTIAL)
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        self.assertNotIn('Object', payload['Event'])

    def test_distribution_changes_at_each_level(self) -> None:
        event = new_event(2)
        one = event.add_attribute('filename', 'community-only.exe', distribution=1)
        two = event.add_attribute('filename', 'connected.exe', distribution=2)
        three = event.add_attribute('filename', 'all.exe', distribution=3)
        inherited = event.add_attribute('filename', 'inherited.exe', distribution=5)

        obj = add_object(event, distribution=1)
        add_object_attribute(obj, 'object-hidden.exe', 5)

        projection = event.project_for_recipient(self.recipient(
            relationship=InstanceRelationship.CONNECTED
        ))

        self.assertEqual(projection.status, ProjectionStatus.PARTIAL)
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        exported = {attribute['uuid'] for attribute in payload['Event']['Attribute']}
        self.assertNotIn(one.uuid, exported)
        self.assertIn(two.uuid, exported)
        self.assertIn(three.uuid, exported)
        self.assertIn(inherited.uuid, exported)
        self.assertNotIn('Object', payload['Event'])

        denied = new_event(1).project_for_recipient(self.recipient(
            relationship=InstanceRelationship.CONNECTED
        ))
        self.assertEqual(denied.status, ProjectionStatus.DENIED)
        self.assertIsNone(denied.to_dict())

    def test_owner_only_event_does_not_become_public_through_inheritance(self) -> None:
        event = new_event(0, owner=organisation('Organisation A', ORG_A_UUID))
        event.add_attribute('filename', 'owner-only.exe', distribution=5)

        other = event.project_for_recipient(self.recipient(
            organisations=['Organisation B'], relationship=InstanceRelationship.SAME_INSTANCE
        ))
        self.assertEqual(other.status, ProjectionStatus.DENIED)
        self.assertIsNone(other.to_dict())

        owner = event.project_for_recipient(self.recipient(
            organisations=['Organisation A'], relationship=InstanceRelationship.SAME_INSTANCE
        ))
        self.assertEqual(owner.status, ProjectionStatus.ALLOWED)
        self.assertIn('owner-only.exe', owner.to_json())

    def test_circular_object_references_are_pruned_without_recursion(self) -> None:
        event = new_event(2)
        first = add_object(event, distribution=5)
        first.uuid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        first.add_attribute('filename', value='first.bin', type='filename',
                            category='Payload delivery', distribution=5)
        second = add_object(event, distribution=5)
        second.uuid = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        second.add_attribute('filename', value='second.bin', type='filename',
                             category='Payload delivery', distribution=5)
        excluded = add_object(event, distribution=1)
        excluded.uuid = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
        excluded.add_attribute('filename', value='excluded.bin', type='filename',
                               category='Payload delivery', distribution=5)

        first.add_reference(second.uuid, 'related-to')
        second.add_reference(first.uuid, 'related-to')
        first.add_reference(first.uuid, 'self-reference')
        first.add_reference(excluded.uuid, 'drops-to-excluded')
        excluded.add_reference(first.uuid, 'from-excluded')

        projection = event.project_for_recipient(self.recipient(
            relationship=InstanceRelationship.CONNECTED
        ))

        self.assertEqual(projection.status, ProjectionStatus.PARTIAL)
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        objects = payload['Event']['Object']
        self.assertEqual({obj['uuid'] for obj in objects}, {first.uuid, second.uuid})
        first_payload = next(obj for obj in objects if obj['uuid'] == first.uuid)
        second_payload = next(obj for obj in objects if obj['uuid'] == second.uuid)
        self.assertEqual(
            {(ref['object_uuid'], ref['referenced_uuid']) for ref in first_payload['ObjectReference']},
            {(first.uuid, second.uuid), (first.uuid, first.uuid)}
        )
        self.assertEqual(
            {(ref['object_uuid'], ref['referenced_uuid']) for ref in second_payload['ObjectReference']},
            {(second.uuid, first.uuid)}
        )
        self.assertEqual(projection.reason_counts().get('referenced_object_excluded'), 1)

        loaded = MISPEvent()
        loaded.load(payload)
        self.assertEqual({obj.uuid for obj in loaded.objects}, {first.uuid, second.uuid})

    def test_circular_analyst_data_does_not_recurse_forever(self) -> None:
        event = new_event(1)
        attribute = event.add_attribute('filename', 'note-cycle.exe', distribution=5)
        first = attribute.add_note(note='first', distribution=5)
        second = attribute.add_note(note='second', distribution=5)
        first.Note = [second]
        second.Note = [first]

        projection = event.project_for_recipient(self.recipient())
        self.assertIn(projection.status, {ProjectionStatus.ALLOWED, ProjectionStatus.PENDING})
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        loaded = MISPEvent()
        loaded.load(payload)
        self.assertEqual(len(loaded.attributes), 1)
        self.assertGreaterEqual(projection.reason_counts().get('analyst_data_cycle', 0), 1)

    def test_missing_membership_table_is_pending_not_public(self) -> None:
        event = new_event(4, sharing_group_id=1)
        event.add_attribute('filename', 'must-not-leak.exe', distribution=5)

        projection = event.project_for_recipient(self.recipient())
        self.assertEqual(projection.status, ProjectionStatus.PENDING)
        self.assertFalse(projection.exportable)
        self.assertIsNone(projection.to_dict())
        self.assertEqual(projection.audit[0].reason, 'missing_sharing_group_membership')

        parent_allowed = new_event(1)
        obj = add_object(parent_allowed, distribution=4, sharing_group_id=9)
        add_object_attribute(obj, 'object-must-not-leak.exe', 5)
        partial = parent_allowed.project_for_recipient(self.recipient())
        self.assertEqual(partial.status, ProjectionStatus.PENDING)
        self.assertFalse(partial.exportable)
        payload = partial.to_dict()
        self.assertIsNotNone(payload)
        self.assertNotIn('Object', payload['Event'])
        self.assertNotIn(obj.uuid, partial.to_json())

    def test_empty_and_incomplete_membership_are_distinct(self) -> None:
        event = new_event(4, sharing_group_id=1)
        event.add_attribute('filename', 'x.exe', distribution=5)

        empty = event.project_for_recipient(self.recipient(sharing_groups={1: []}))
        self.assertEqual(empty.status, ProjectionStatus.DENIED)
        self.assertIsNone(empty.to_dict())
        self.assertEqual(empty.audit[0].reason, 'recipient_not_in_sharing_group')

        incomplete = event.project_for_recipient(self.recipient(
            sharing_groups={1: {'uuid': SG_1_UUID, 'members': None}}
        ))
        self.assertEqual(incomplete.status, ProjectionStatus.PENDING)
        self.assertEqual(incomplete.audit[0].reason, 'incomplete_sharing_group_membership')

    def test_sharing_group_identity_conflicts_stay_pending(self) -> None:
        event = new_event(4, sharing_group_id=1)
        event.add_attribute('filename', 'x.exe', distribution=5)

        conflicting = event.project_for_recipient(self.recipient(
            sharing_groups={
                1: {'uuid': SG_1_UUID, 'members': ['Organisation A']},
                SG_1_UUID: {'uuid': SG_2_UUID, 'members': ['Organisation A']},
            }
        ))
        self.assertEqual(conflicting.status, ProjectionStatus.PENDING)
        self.assertIsNone(conflicting.to_dict())
        self.assertEqual(conflicting.audit[0].reason, 'sharing_group_identity_conflict')

        embedded = new_event(4, sharing_group_id=1)
        embedded.add_attribute('filename', 'x.exe', distribution=5)
        sharing_group = MISPSharingGroup()
        sharing_group.from_dict(id=1, uuid=SG_2_UUID, name='Conflicting group')
        embedded.SharingGroup = sharing_group
        embedded_conflict = embedded.project_for_recipient(self.recipient(
            sharing_groups={1: {'uuid': SG_1_UUID, 'members': ['Organisation A']}}
        ))
        self.assertEqual(embedded_conflict.status, ProjectionStatus.PENDING)
        self.assertEqual(embedded_conflict.audit[0].reason, 'sharing_group_identity_conflict')

    def test_sharing_group_can_be_described_by_uuid_and_membership_is_not_leaked(self) -> None:
        event = new_event(4, sharing_group_id=1)
        sharing_group = MISPSharingGroup()
        sharing_group.from_dict(id=1, uuid=SG_1_UUID, name='Caller independent group')
        sharing_group.add_sgorg({'Organisation': {'name': 'Unrelated partner',
                                                  'uuid': 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'},
                                 'extend': False})
        event.SharingGroup = sharing_group
        event.add_attribute('filename', 'x.exe', distribution=5)

        projection = event.project_for_recipient(self.recipient(
            sharing_groups={SG_1_UUID: {'members': ['Organisation A']}}
        ))

        self.assertEqual(projection.status, ProjectionStatus.ALLOWED)
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        self.assertEqual(payload['Event']['distribution'], '4')
        self.assertEqual(payload['Event']['sharing_group_id'], '1')
        encoded = projection.to_json()
        self.assertIsNotNone(encoded)
        self.assertNotIn('Unrelated partner', encoded)
        self.assertNotIn('cccccccc-cccc-4ccc-8ccc-cccccccccccc', encoded)
        loaded = MISPEvent()
        loaded.load(payload)
        self.assertEqual(int(loaded.sharing_group_id), 1)

    def test_original_event_and_recipient_mapping_are_unchanged(self) -> None:
        event = new_event(4, sharing_group_id=1)
        event.add_attribute('filename', 'top.exe', distribution=5)
        obj = add_object(event, distribution=4, sharing_group_id=1)
        add_object_attribute(obj, 'object.exe', 5)
        event.add_attribute('filename', 'excluded.exe', distribution=1)

        mapping = {
            1: {'uuid': SG_1_UUID, 'members': ['Organisation A']},
            2: {'uuid': SG_2_UUID, 'members': ['Organisation B']},
        }
        mapping_before = copy.deepcopy(mapping)
        event_before = event.to_json(sort_keys=True)
        event_hash_before = hashlib.sha256(event_before.encode()).hexdigest()
        object_uuid_before = obj.uuid
        attribute_uuids_before = [attribute.uuid for attribute in obj.attributes]

        second = event.project_for_recipient(self.recipient(
            organisations=['Organisation B'],
            relationship=InstanceRelationship.CONNECTED,
            sharing_groups=mapping
        ))
        first = event.project_for_recipient(self.recipient(
            relationship=InstanceRelationship.CONNECTED,
            sharing_groups=mapping
        ))

        self.assertEqual(event.to_json(sort_keys=True), event_before)
        self.assertEqual(
            hashlib.sha256(event.to_json(sort_keys=True).encode()).hexdigest(),
            event_hash_before
        )
        self.assertEqual(mapping, mapping_before)
        self.assertEqual(obj.uuid, object_uuid_before)
        self.assertEqual([attribute.uuid for attribute in obj.attributes], attribute_uuids_before)
        self.assertIsNot(first.event, event)
        self.assertIsNot(first.event.objects[0], obj)
        self.assertEqual(first.status, ProjectionStatus.PARTIAL)
        self.assertEqual(second.status, ProjectionStatus.DENIED)

        first.event.attributes[0].value = 'mutated copy'
        self.assertEqual(event.attributes[0].value, 'top.exe')
        self.assertIsNone(second.to_json())

    def test_projection_is_readable_misp_json(self) -> None:
        event = new_event(1)
        kept = event.add_attribute('filename', 'kept.exe', distribution=5)
        removed = event.add_attribute('filename', 'removed.exe', distribution=0)
        obj = add_object(event, distribution=5)
        kept_object_attribute = add_object_attribute(obj, 'kept-object.exe', 5)

        projection = event.project_for_recipient(self.recipient(
            organisations=['Organisation B']
        ))
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        self.assertIn('Event', payload)

        loaded = MISPEvent()
        loaded.load(payload)
        self.assertEqual({attribute.uuid for attribute in loaded.attributes}, {kept.uuid})
        self.assertNotIn(removed.uuid, {attribute.uuid for attribute in loaded.attributes})
        self.assertEqual({obj.uuid for obj in loaded.objects}, {event.objects[0].uuid})
        self.assertEqual(
            {attribute.uuid for attribute in loaded.objects[0].attributes},
            {kept_object_attribute.uuid}
        )
        loaded_from_json = MISPEvent()
        loaded_from_json.load(projection.to_json())
        self.assertEqual({attribute.uuid for attribute in loaded_from_json.attributes}, {kept.uuid})

    def test_removing_a_restricted_sibling_does_not_widen_its_sibling(self) -> None:
        event = new_event(2)
        obj = add_object(event, distribution=4, sharing_group_id=1)
        restricted = add_object_attribute(obj, 'restricted.exe', 4, sharing_group_id=2)
        sibling = add_object_attribute(obj, 'sibling.exe', 5)

        projection = event.project_for_recipient(self.recipient(
            relationship=InstanceRelationship.CONNECTED,
            sharing_groups={
                1: {'uuid': SG_1_UUID, 'members': ['Organisation A']},
                2: {'uuid': SG_2_UUID, 'members': ['Organisation B']},
            }
        ))
        self.assertEqual(projection.status, ProjectionStatus.PARTIAL)
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        exported_object = payload['Event']['Object'][0]
        self.assertEqual(exported_object['distribution'], '4')
        self.assertEqual(exported_object['sharing_group_id'], '1')
        exported_attributes = exported_object['Attribute']
        self.assertEqual([attribute['uuid'] for attribute in exported_attributes], [sibling.uuid])
        self.assertEqual(exported_attributes[0]['distribution'], '5')
        self.assertNotIn(restricted.uuid, projection.to_json())

        without_restricted = new_event(2)
        other_object = add_object(without_restricted, distribution=4, sharing_group_id=1)
        other_sibling = add_object_attribute(other_object, 'sibling.exe', 5)
        other_projection = without_restricted.project_for_recipient(self.recipient(
            relationship=InstanceRelationship.CONNECTED,
            sharing_groups={
                1: {'uuid': SG_1_UUID, 'members': ['Organisation A']},
                2: {'uuid': SG_2_UUID, 'members': ['Organisation B']},
            }
        ))
        self.assertEqual(other_projection.status, ProjectionStatus.ALLOWED)
        other_payload = other_projection.to_dict()
        self.assertIsNotNone(other_payload)
        self.assertEqual(other_payload['Event']['Object'][0]['Attribute'][0]['uuid'],
                         other_sibling.uuid)
        self.assertEqual(other_payload['Event']['Object'][0]['Attribute'][0]['distribution'], '5')

    def test_audit_contains_identifiers_and_reasons_only(self) -> None:
        event = new_event(1)
        secret = 'SECRET-VALUE-DO-NOT-AUDIT'
        event.add_attribute('filename', secret, distribution=0, comment='SECRET-COMMENT')
        event.add_attribute('filename', 'kept.exe', distribution=5)

        projection = event.project_for_recipient(self.recipient(
            organisations=['Organisation B']
        ))
        self.assertEqual(projection.status, ProjectionStatus.PARTIAL)
        serialised_audit = json.dumps([entry.to_dict() for entry in projection.audit])
        self.assertNotIn(secret, serialised_audit)
        self.assertNotIn('SECRET-COMMENT', serialised_audit)
        for entry in projection.audit:
            self.assertLessEqual(
                set(entry.to_dict()),
                {'kind', 'reason', 'uuid', 'id', 'sharing_group_id'}
            )

    def test_search_context_is_removed_and_timestamps_are_preserved(self) -> None:
        event = new_event(1)
        event.timestamp = '1700000000'
        kept = event.add_attribute('filename', 'kept.exe', distribution=5)
        kept.timestamp = '1700000001'
        excluded = event.add_attribute('filename', 'excluded.exe', distribution=0)
        kept.Event = event
        kept.RelatedAttribute = [excluded]

        projection = event.project_for_recipient(self.recipient(
            organisations=['Organisation B']
        ))
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        attribute_payload = payload['Event']['Attribute'][0]
        self.assertEqual(attribute_payload['uuid'], kept.uuid)
        self.assertIn('timestamp', attribute_payload)
        self.assertIn('timestamp', payload['Event'])
        self.assertNotIn('Event', attribute_payload)
        self.assertNotIn('RelatedAttribute', attribute_payload)
        self.assertNotIn('excluded.exe', projection.to_json())

    def test_derived_content_does_not_expose_excluded_items(self) -> None:
        event = new_event(2)
        kept = event.add_attribute('filename', 'kept.exe', distribution=5)
        excluded = event.add_attribute('filename', 'excluded.exe', distribution=1)
        excluded.add_tag('excluded-tag')
        excluded.add_sighting({'value': 'excluded.exe', 'type': '0', 'source': 'sensor'})
        kept.add_sighting({'value': 'kept.exe', 'type': '0', 'source': 'sensor'})
        kept.RelatedAttribute = [excluded]
        kept.ShadowAttribute = [excluded]
        event.ShadowAttribute = [excluded]

        keeper = add_object(event, distribution=5)
        hidden = add_object(event, distribution=1)
        kept.add_relationship('Object', keeper.uuid, 'related-to', distribution=5)
        kept.add_relationship('Object', hidden.uuid, 'related-to', distribution=5)
        keeper.add_reference(hidden.uuid, 'related-to')

        event.RelatedEvent = [{'Event': new_event(1)}]
        event.add_cryprographic_key(
            parent_type='Object', key_data='data', type='x509', uuid=str(uuid4()),
            fingerprint='fingerprint', timestamp='1234567890',
            parent_uuid=hidden.uuid
        )

        projection = event.project_for_recipient(self.recipient(
            relationship=InstanceRelationship.CONNECTED
        ))
        payload = projection.to_dict()
        self.assertIsNotNone(payload)
        encoded = projection.to_json()
        self.assertIsNotNone(encoded)
        self.assertNotIn(excluded.uuid, encoded)
        self.assertNotIn(hidden.uuid, encoded)
        self.assertNotIn('excluded-tag', encoded)
        self.assertIn(kept.uuid, encoded)
        self.assertIn(keeper.uuid, encoded)

        kept_payload = payload['Event']['Attribute'][0]
        self.assertEqual([sighting['value'] for sighting in kept_payload['Sighting']], ['kept.exe'])
        self.assertNotIn('RelatedAttribute', kept_payload)
        self.assertNotIn('ShadowAttribute', kept_payload)
        self.assertEqual(kept_payload['Relationship'][0]['related_object_uuid'], keeper.uuid)
        self.assertEqual(len(kept_payload['Relationship']), 1)
        self.assertNotIn('ObjectReference', payload['Event']['Object'][0])
        self.assertNotIn('RelatedEvent', payload['Event'])
        self.assertNotIn('CryptographicKey', payload['Event'])
        reasons = projection.reason_counts()
        self.assertGreaterEqual(reasons.get('shadow_attribute_not_projected', 0), 2)
        self.assertGreaterEqual(reasons.get('related_event_not_projected', 0), 1)
        self.assertGreaterEqual(reasons.get('cryptographic_key_parent_excluded', 0), 1)

    def test_version_and_unsupported_analyst_data(self) -> None:
        event = new_event(1)
        attribute = event.add_attribute('filename', 'kept.exe', distribution=5)
        attribute.add_note(note='analyst note', distribution=5)

        unsupported_contract = event.project_for_recipient(self.recipient(version='999'))
        self.assertEqual(unsupported_contract.status, ProjectionStatus.PENDING)
        self.assertIsNone(unsupported_contract.to_dict())
        self.assertEqual(unsupported_contract.audit[0].reason, 'unsupported_recipient_version')

        unsupported_server = event.project_for_recipient(self.recipient(misp_version='0.1'))
        self.assertEqual(unsupported_server.status, ProjectionStatus.PENDING)
        self.assertIsNone(unsupported_server.to_dict())
        self.assertEqual(unsupported_server.audit[0].reason, 'unsupported_misp_version')

        old_server = event.project_for_recipient(self.recipient(misp_version='2.4.100'))
        self.assertEqual(old_server.status, ProjectionStatus.PENDING)
        self.assertFalse(old_server.exportable)
        old_payload = old_server.to_dict()
        self.assertIsNotNone(old_payload)
        self.assertIn(attribute.uuid, old_server.to_json())
        self.assertNotIn('analyst note', old_server.to_json())
        self.assertEqual(old_server.audit[0].reason, 'unsupported_misp_version')

        supported = event.project_for_recipient(self.recipient(misp_version='2.4.186'))
        self.assertEqual(supported.status, ProjectionStatus.ALLOWED)
        self.assertIn('analyst note', supported.to_json())

    def test_missing_recipient_description_stays_pending(self) -> None:
        event = new_event(1)
        event.add_attribute('filename', 'x.exe', distribution=5)

        no_relationship = event.project_for_recipient(RecipientContext(
            organisations=['Organisation A']
        ))
        self.assertEqual(no_relationship.status, ProjectionStatus.PENDING)
        self.assertEqual(no_relationship.audit[0].reason, 'missing_instance_relationship')

        no_orgs = event.project_for_recipient(RecipientContext(
            instance_relationship=InstanceRelationship.SAME_INSTANCE
        ))
        self.assertEqual(no_orgs.status, ProjectionStatus.PENDING)
        self.assertEqual(no_orgs.audit[0].reason, 'missing_recipient_organisations')

    def test_invalid_distribution_is_pending_not_inherited(self) -> None:
        event = new_event(1)
        attribute = event.add_attribute('filename', 'bad.exe')
        attribute.distribution = 99

        projection = event.project_for_recipient(self.recipient())
        self.assertEqual(projection.status, ProjectionStatus.PENDING)
        self.assertFalse(projection.exportable)
        self.assertEqual(projection.audit[0].reason, 'unsupported_distribution')
        self.assertNotIn('bad.exe', projection.to_json())

    def test_projection_result_type(self) -> None:
        event = new_event(1)
        projection = event.recipient_projection(self.recipient())
        self.assertIsInstance(projection, ShareProjection)
        self.assertIs(projection.to_misp_event(), projection.event)


if __name__ == '__main__':
    unittest.main()
