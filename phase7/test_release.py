import hashlib,json,pathlib,tempfile,unittest,zipfile
import release
class ReleaseVerification(unittest.TestCase):
 def make(self,p,mutate=False,badpath=False):
  data={n:b'test' for n in ('phase6/installer.py','phase6/system_installer.py','phase3/requirements-ubuntu20-py312.lock','phase7/release.py','phase7/INSTALL_GUIDE.md','phase7/ADMIN_GUIDE.md','phase7/USER_GUIDE.md','phase1/server.py','wheels/test.whl')}
  data['RELEASE.json']=json.dumps({'git_commit':'a'*40,'format':1,'platform':'linux-x86_64-python3.12','offline':True}).encode()
  if badpath: data['../escape']=b'escape'
  manifest={n:hashlib.sha256(b).hexdigest() for n,b in data.items()}
  if mutate: data['phase1/server.py']=b'tampered'
  with zipfile.ZipFile(p,'w') as z:
   for name,value in data.items():
    i=zipfile.ZipInfo(name); i.external_attr=0o100644<<16; z.writestr(i,value)
   i=zipfile.ZipInfo(release.MANIFEST); i.external_attr=0o100644<<16; z.writestr(i,json.dumps(manifest))
 def test_digest_and_version(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'r.zip'; self.make(p); self.assertEqual(release.verify(p,'a'*40)['git_commit'],'a'*40)
   with self.assertRaisesRegex(ValueError,'wrong Git'): release.verify(p,'b'*40)
   self.make(p,mutate=True)
   with self.assertRaisesRegex(ValueError,'digest mismatch'): release.verify(p)
 def test_reject_traversal_and_unsafe_destination(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'r.zip'; self.make(p,badpath=True)
   with self.assertRaisesRegex(ValueError,'unsafe archive'): release.verify(p)
   self.make(p); target=pathlib.Path(d)/'out'; target.mkdir(mode=0o700); (target/'existing').write_text('keep')
   with self.assertRaisesRegex(ValueError,'empty private'): release.extract(p,target)
   self.assertEqual((target/'existing').read_text(),'keep')
if __name__=='__main__': unittest.main(verbosity=2)
