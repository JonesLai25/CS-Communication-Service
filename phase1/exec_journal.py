"""Durable execution bookkeeping; no process is launched by this module."""
import base64,hashlib,json,time,uuid
from registry import Conflict,Denied,Limited
from deployment_policy import validate

MAX_OUTPUT=2048
class ExecJournal:
 def __init__(self,registry,policy=None): self.registry=registry; self.policy=validate({} if policy is None else policy)
 def initialize(self):
  def op(db):
   db.execute('CREATE TABLE IF NOT EXISTS exec_jobs(owner TEXT NOT NULL,id TEXT NOT NULL,device TEXT NOT NULL,body BLOB NOT NULL,state TEXT NOT NULL,exit_code INTEGER,stdout BLOB NOT NULL,stderr BLOB NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(owner,id))')
   columns={r[1] for r in db.execute('PRAGMA table_info(exec_jobs)')}
   for name,kind in (('worker_pid','INTEGER'),('worker_start','TEXT'),('worker_boot','TEXT')):
    if name not in columns: db.execute('ALTER TABLE exec_jobs ADD COLUMN '+name+' '+kind)
   # A server crash may leave an external effect; never launch it again automatically.
   db.execute("UPDATE exec_jobs SET state='unknown',updated=? WHERE state IN ('queued','running')",(int(time.time()),))
   db.execute("UPDATE requests SET state='unknown',result='' WHERE (owner,id) IN (SELECT owner,id FROM exec_jobs WHERE state='unknown')")
  self.registry.transaction(op)
 @staticmethod
 def encode(owner,rid,request):
  if not isinstance(rid,str) or str(uuid.UUID(rid))!=rid or not isinstance(request,dict) or set(request)!={'operation','workspace','argv','timeout_seconds'}: raise ValueError('invalid execution request')
  if request['operation']!='exec' or request['workspace']!=owner: raise Denied()
  args=request['argv']; timeout=request['timeout_seconds']
  if not isinstance(args,list) or not 1<=len(args)<=64 or any(not isinstance(a,str) or not a or '\0' in a or len(a.encode())>4096 for a in args) or sum(len(a.encode()) for a in args)>16384: raise ValueError('invalid argv')
  if type(timeout) is not int or not 1<=timeout<=300: raise ValueError('invalid timeout')
  return json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
 @staticmethod
 def _allowed(db,owner,device):
  if not db.execute('SELECT 1 FROM devices d JOIN users u ON u.owner=d.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,device)).fetchone(): raise Denied()
 def submit(self,owner,device,rid,request):
  raw=self.encode(owner,rid,request); digest=hashlib.sha256(raw).digest(); now=int(time.time())
  if request['timeout_seconds']>self.policy['timeout_seconds']: raise ValueError('timeout exceeds deployment policy')
  def op(db):
   self._allowed(db,owner,device)
   old=db.execute('SELECT digest,state FROM requests WHERE owner=? AND id=?',(owner,rid)).fetchone()
   if old:
    if old[0]!=digest or not db.execute('SELECT 1 FROM exec_jobs WHERE owner=? AND id=? AND device=?',(owner,rid,device)).fetchone(): raise Conflict()
    return {'new':False,'state':old[1]}
   if db.execute("SELECT count(*) FROM exec_jobs WHERE owner=? AND state!='expired'",(owner,)).fetchone()[0]>=self.policy['retained_per_user'] or db.execute("SELECT count(*) FROM exec_jobs WHERE state!='expired'").fetchone()[0]>=self.policy['retained_total']: raise Limited()
   if db.execute("SELECT count(*) FROM exec_jobs WHERE state IN ('queued','running')").fetchone()[0]>=1: raise Limited()
   db.execute("INSERT INTO requests VALUES(?,?,?,'queued','')",(owner,rid,digest))
   db.execute("INSERT INTO exec_jobs(owner,id,device,body,state,exit_code,stdout,stderr,created,updated) VALUES(?,?,?,?,'queued',NULL,x'',x'',?,?)",(owner,rid,device,raw,now,now))
   return {'new':True,'state':'queued'}
  return self.registry.transaction(op)
 def attach(self,owner,rid,pid,start,boot):
  def op(db): return db.execute("UPDATE exec_jobs SET worker_pid=?,worker_start=?,worker_boot=? WHERE owner=? AND id=? AND state='running'",(pid,start,boot,owner,rid)).rowcount==1
  return self.registry.transaction(op)
 def claim(self,owner,rid):
  def op(db):
   row=db.execute("SELECT device FROM exec_jobs WHERE owner=? AND id=? AND state='queued'",(owner,rid)).fetchone()
   if row and not db.execute('SELECT 1 FROM devices d JOIN users u ON u.owner=d.owner WHERE d.owner=? AND d.device=? AND d.enabled=1 AND u.enabled=1',(owner,row[0])).fetchone():
    db.execute("UPDATE exec_jobs SET state='cancelled',updated=? WHERE owner=? AND id=? AND state='queued'",(int(time.time()),owner,rid)); db.execute("UPDATE requests SET state='cancelled' WHERE owner=? AND id=?",(owner,rid)); return False
   n=db.execute("UPDATE exec_jobs SET state='running',updated=? WHERE owner=? AND id=? AND state='queued'",(int(time.time()),owner,rid)).rowcount
   if n: db.execute("UPDATE requests SET state='running' WHERE owner=? AND id=?",(owner,rid))
   return bool(n)
  return self.registry.transaction(op)
 def finish(self,owner,rid,state,code,stdout,stderr):
  if state not in ('succeeded','failed','timed_out','cancelled','unknown') or not isinstance(stdout,bytes) or not isinstance(stderr,bytes) or len(stdout)+len(stderr)>MAX_OUTPUT or code is not None and type(code) is not int: raise ValueError('invalid result')
  def op(db):
   n=db.execute("UPDATE exec_jobs SET state=?,exit_code=?,stdout=?,stderr=?,updated=? WHERE owner=? AND id=? AND state='running'",(state,code,stdout,stderr,int(time.time()),owner,rid)).rowcount
   if n: db.execute('UPDATE requests SET state=?,result=? WHERE owner=? AND id=?',(state,'',owner,rid))
   return bool(n)
  return self.registry.transaction(op)
 def cancel_queued(self,owner,device,rid):
  def op(db):
   self._allowed(db,owner,device)
   row=db.execute('SELECT state FROM exec_jobs WHERE owner=? AND id=? AND device=?',(owner,rid,device)).fetchone()
   if not row: raise Denied()
   if row[0]=='queued':
    db.execute("UPDATE exec_jobs SET state='cancelled',updated=? WHERE owner=? AND id=? AND state='queued'",(int(time.time()),owner,rid)); db.execute("UPDATE requests SET state='cancelled' WHERE owner=? AND id=?",(owner,rid)); return 'cancelled'
   return row[0]
  return self.registry.transaction(op)
 def prune_results(self,days,now=None):
  if type(days) is not int or not 1<=days<=3650: raise ValueError('invalid execution retention')
  cutoff=(int(time.time()) if now is None else now)-days*86400
  if type(cutoff) is not int: raise ValueError('invalid time')
  def op(db):
   if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='exec_jobs'").fetchone(): return 0
   rows=list(db.execute("SELECT owner,id FROM exec_jobs WHERE state IN ('succeeded','failed','timed_out','cancelled') AND updated<? ORDER BY updated LIMIT 512",(cutoff,)))
   for owner,rid in rows:
    db.execute("UPDATE exec_jobs SET state='expired',body=x'',stdout=x'',stderr=x'',exit_code=NULL,worker_pid=NULL,worker_start=NULL,worker_boot=NULL WHERE owner=? AND id=?",(owner,rid))
    db.execute("UPDATE requests SET state='expired',result='' WHERE owner=? AND id=?",(owner,rid))
   return len(rows)
  return self.registry.transaction(op)
 def result(self,owner,device,rid):
  def op(db):
   self._allowed(db,owner,device)
   if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='exec_jobs'").fetchone(): return None
   row=db.execute('SELECT state,exit_code,stdout,stderr FROM exec_jobs WHERE owner=? AND id=? AND device=?',(owner,rid,device)).fetchone()
   if not row: return None
   return {'state':row[0],'exit_code':row[1],'stdout_b64':base64.b64encode(row[2]).decode('ascii'),'stderr_b64':base64.b64encode(row[3]).decode('ascii')}
  return self.registry.transaction(op)
