import pathlib,sqlite3,sys,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'phase1'))
from registry import Registry
class Retention(unittest.TestCase):
 def test_age_and_count_prune_without_touching_identity(self):
  with tempfile.TemporaryDirectory() as d:
   r=Registry(str(pathlib.Path(d)/'db')); r.initialize(); r.add_user('alice'); now=20000000
   with sqlite3.connect(r.path) as db:
    db.execute('DELETE FROM audit'); db.executemany('INSERT INTO audit VALUES(?,?,?,?)',[(now-91*86400,'alice','','old')]*10+[(now-i,'alice','','recent') for i in range(120)])
   self.assertEqual(r.prune_audit(90,100,now),30)
   with sqlite3.connect(r.path) as db:
    self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0],100); self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE event='old'").fetchone()[0],0); self.assertEqual(db.execute("SELECT count(*) FROM users WHERE owner='alice'").fetchone()[0],1)
 def test_invalid_policy_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   r=Registry(str(pathlib.Path(d)/'db')); r.initialize()
   for days,cap in ((0,100),(90,99),(True,100),(90,1000001)):
    with self.assertRaises(ValueError): r.prune_audit(days,cap)
if __name__=='__main__': unittest.main(verbosity=2)
