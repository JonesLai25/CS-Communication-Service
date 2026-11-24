"""Mutate only a temporary copy of the published release and require rejection."""
import os,pathlib,tempfile,unittest,zipfile
from release import verify
class ActualRelease(unittest.TestCase):
 def test_mutated_product_source_rejected(self):
  source=pathlib.Path(os.environ['CS_PHASE7_ARTIFACT']); expected=os.environ['CS_PHASE7_COMMIT']; verify(source,expected)
  with tempfile.TemporaryDirectory(prefix='cs-release-mutation-') as d:
   target=pathlib.Path(d)/'modified.zip'
   with zipfile.ZipFile(source) as original,zipfile.ZipFile(target,'w') as mutant:
    for item in original.infolist():
     value=original.read(item.filename)
     if item.filename=='phase1/server.py': value+=b'\n# known isolated mutation\n'
     mutant.writestr(item,value)
   with self.assertRaisesRegex(ValueError,'digest mismatch'): verify(target)
  verify(source,expected)
if __name__=='__main__': unittest.main(verbosity=2)
