"""Kill only a child created by this test; no host power or service changes."""
import hashlib, pathlib, select, sqlite3, subprocess, sys, tempfile, unittest
from registry import Registry
SCRIPT='''import hashlib,signal,sqlite3,sys
p,rid,commit=sys.argv[1:]
db=sqlite3.connect(p,isolation_level=None); db.execute('BEGIN IMMEDIATE')
db.execute('INSERT INTO requests VALUES(?,?,?,?,?)',('alice',rid,hashlib.sha256(b"safe").digest(),'running',''))
db.execute('INSERT INTO effects VALUES(?,?)',('alice',rid))
db.execute("UPDATE requests SET state='succeeded',result='recorded' WHERE owner='alice' AND id=?",(rid,))
if commit=='yes': db.execute('COMMIT')
print('ready',flush=True); signal.pause()
'''
class Crash(unittest.TestCase):
 def test_transaction_interruption(self):
  with tempfile.TemporaryDirectory() as d:
   path=str(pathlib.Path(d)/'db'); reg=Registry(path); reg.initialize(); reg.provision('alice','device',bytes(32))
   for rid,commit in [('before','no'),('after','yes')]:
    proc=subprocess.Popen([sys.executable,'-c',SCRIPT,path,rid,commit],stdout=subprocess.PIPE,text=True)
    try:
     if not select.select([proc.stdout],[],[],5)[0]: self.fail('child startup timeout')
     self.assertEqual(proc.stdout.readline().strip(),'ready'); proc.kill(); proc.wait(timeout=5)
    finally:
     if proc.poll() is None: proc.kill(); proc.wait(timeout=5)
     proc.stdout.close()
   self.assertIsNone(reg.result('alice','before','device'))
   self.assertEqual(reg.result('alice','after','device')['state'],'succeeded')
   self.assertFalse(reg.execute('alice','after',b'safe','device')['new'])
   with sqlite3.connect(path) as db:
    self.assertEqual(db.execute("SELECT count(*) FROM effects WHERE id='before'").fetchone()[0],0)
    self.assertEqual(db.execute("SELECT count(*) FROM effects WHERE id='after'").fetchone()[0],1)
if __name__=='__main__': unittest.main(verbosity=2)
