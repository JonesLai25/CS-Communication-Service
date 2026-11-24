import json,pathlib,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'phase1'))
from deployment_policy import DEFAULT,validate,load
class Policy(unittest.TestCase):
 def test_defaults_and_safe_overrides(self):
  value=validate({'memory_mib':96,'workspace_mib':8,'output_bytes':4,'tasks':16,'cpus':1,'timeout_seconds':5})
  self.assertEqual(value['memory_mib'],96); self.assertEqual(value['output_bytes'],4); self.assertEqual(validate({}),DEFAULT)
 def test_invalid_or_unsafe_values_fail_closed(self):
  for bad in ({'cpus':5},{'memory_mib':1025},{'workspace_mib':128,'memory_mib':80},{'output_bytes':True},{'tasks':7},{'unknown':1},{'retained_per_user':20,'retained_total':10}):
   with self.subTest(value=bad),self.assertRaises(ValueError): validate(bad)
 def test_policy_file_permissions_and_duplicate_keys(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'policy'; p.write_text(json.dumps({'memory_mib':96})); p.chmod(0o600); self.assertEqual(load(p)['memory_mib'],96)
   p.write_text('{"tasks":16,"tasks":32}')
   with self.assertRaises(ValueError): load(p)
   p.write_text('{}'); p.chmod(0o644)
   with self.assertRaises(ValueError): load(p)
if __name__=='__main__': unittest.main(verbosity=2)
