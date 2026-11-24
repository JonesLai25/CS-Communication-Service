"""Build only a temporary, test-owned installation; never a host deployment."""
import pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools')); sys.path.insert(0,str(ROOT/'phase6'))
from resource_guard import enforce
enforce(144*1024*1024,128*1024*1024,64,400000)
from installer import install
prefix=pathlib.Path(sys.argv[1]); parent=prefix.parent
if prefix.name!='product' or parent.parent!=pathlib.Path('/tmp') or not parent.name.startswith('cs-phase6-e2e.'): raise SystemExit('invalid test-only prefix')
result=install(prefix,ROOT/'.local-test/python312/bin/python3',ROOT/'.local-test/ubuntu20-py312-wheels',ROOT/'phase3/requirements-ubuntu20-py312.lock')
if result['status']!='installed': raise SystemExit('unexpected fixture status')
print('offline isolated fixture installed')
