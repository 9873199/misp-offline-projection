import json,unittest,hashlib
from pymisp import InstanceRelationship,RecipientContext
from tests.test_sharing_projection import new_event,add_object,add_object_attribute

class Contract(unittest.TestCase):
 def recipient(self):return RecipientContext(organisations=['External Partner'],instance_relationship=InstanceRelationship.CONNECTED)
 def event(self):
  e=new_event(3);target=add_object(e,distribution=5);add_object_attribute(target,'visible.txt',5);hidden=add_object_attribute(target,'private-fixture-marker.txt',0);return e,target,hidden
 def test_restricted_child_is_removed(self):
  e,_,hidden=self.event();p=e.project_for_recipient(self.recipient());self.assertTrue(p.exportable);self.assertNotIn('private-fixture-marker.txt',p.to_json());self.assertNotIn(hidden.uuid,p.to_json())
 def test_expanded_object_reference_cannot_restore_hidden_child(self):
  e,target,hidden=self.event();source=add_object(e,distribution=5);add_object_attribute(source,'source.txt',5)
  ref=source.add_reference(target.uuid,'related-to');ref.Object=target.to_dict()
  p=e.project_for_recipient(self.recipient());self.assertTrue(p.exportable)
  text=p.to_json();print('expanded reference carries excluded child:',hidden.uuid in text,flush=True)
  self.assertNotIn('private-fixture-marker.txt',text);self.assertNotIn(hidden.uuid,text)
 def test_input_event_remains_unchanged(self):
  e,_,_=self.event();before=e.to_json();e.project_for_recipient(self.recipient());self.assertEqual(e.to_json(),before)
 def test_absent_sharing_group_membership_fails_closed(self):
  e=new_event(4,sharing_group_id=77);e.add_attribute('filename','group-only.txt',distribution=5)
  p=e.project_for_recipient(self.recipient());self.assertFalse(p.exportable);self.assertIsNone(p.to_dict())
if __name__=='__main__':unittest.main(verbosity=2)
