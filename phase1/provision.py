"""Local-only bootstrap for the Phase 1 development slice; NOT enrollment."""
import argparse, os, pathlib, re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from registry import Registry
p=argparse.ArgumentParser(); p.add_argument('--db',required=True); p.add_argument('--owner',required=True); p.add_argument('--device',required=True); p.add_argument('--public-key',required=True); a=p.parse_args()
for value in (a.owner,a.device):
 if not re.fullmatch('[A-Za-z0-9_-]{1,64}',value): p.error('invalid owner or device')
pub=pathlib.Path(a.public_key).read_bytes(); Ed25519PublicKey.from_public_bytes(pub)
r=Registry(a.db)
if not os.path.exists(a.db): r.initialize()
else:
 st=os.lstat(a.db)
 if not pathlib.Path(a.db).is_file() or os.path.islink(a.db) or st.st_uid!=os.geteuid() or st.st_mode & 0o077: raise SystemExit('refusing unsafe registry')
r.provision(a.owner,a.device,pub); print('public key registered locally')
