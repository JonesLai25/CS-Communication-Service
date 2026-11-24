"""Install the actual immutable release into a test-owned temporary prefix."""
import os,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'phase7')]
from resource_guard import enforce
from release import extract
enforce(144*1024*1024,128*1024*1024,64,400000)
prefix=pathlib.Path(sys.argv[1]); archive=pathlib.Path(sys.argv[2]); case=prefix.parent
if prefix.name!='product' or case.parent!=pathlib.Path('/tmp') or not case.name.startswith('cs-phase7-e2e.') or archive.resolve().parent!=ROOT.parent.resolve(): raise SystemExit('invalid test-only path')
package=case/'release'; package.mkdir(mode=0o700); meta=extract(archive,package)
command=[str(ROOT/'.local-test/python312/bin/python3'),'-B',str(package/'phase6/installer.py'),'install','--prefix',str(prefix),'--python',str(ROOT/'.local-test/python312/bin/python3'),'--wheelhouse',str(package/'wheels'),'--lock',str(package/'phase3/requirements-ubuntu20-py312.lock')]
r=subprocess.run(command,capture_output=True,text=True,timeout=120)
if r.returncode: raise SystemExit('release install failed: '+r.stderr[-2000:])
print('verified release commit:',meta['git_commit'],flush=True); print(r.stdout,flush=True)
