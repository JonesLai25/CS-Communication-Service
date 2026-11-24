"""Bounded runner for the isolated large-file TLS test and its child processes."""
from resource_guard import enforce
enforce(144*1024*1024,128*1024*1024,64,300000)
import os,pathlib,signal,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
mode=sys.argv[1] if len(sys.argv)==2 else 'compressible'
if mode not in ('compressible','incompressible'): raise SystemExit('invalid mode')
name='test_large_e2e.py' if mode=='compressible' else 'test_large_e2e_incompressible.py'
p=subprocess.Popen([str(root/'.venv/bin/python'),'-B','-O',str(root/'phase3'/name)],cwd=str(root),start_new_session=True)
try:
 try: code=p.wait(timeout=180)
 except subprocess.TimeoutExpired:
  os.killpg(p.pid,signal.SIGTERM)
  try: p.wait(timeout=5)
  except subprocess.TimeoutExpired: os.killpg(p.pid,signal.SIGKILL); p.wait(timeout=5)
  raise SystemExit('isolated large-file test exceeded 180s')
 if code: raise SystemExit(code)
finally:
 if p.poll() is None:
  os.killpg(p.pid,signal.SIGTERM)
  try: p.wait(timeout=5)
  except subprocess.TimeoutExpired: os.killpg(p.pid,signal.SIGKILL); p.wait(timeout=5)
