"""Explicit local cleanup of one known transfer's encrypted staging only."""
import argparse,json,sys
from resume_client import cleanup_local,ResumeFailure

def main():
 p=argparse.ArgumentParser(); p.add_argument('--directory',required=True); p.add_argument('--transfer-id',required=True); a=p.parse_args()
 cleanup_local(a.directory,a.transfer_id); print(json.dumps({'status':'staging_cleaned','transfer_id':a.transfer_id}))
if __name__=='__main__':
 try: main()
 except (OSError,ValueError,ResumeFailure) as e: print(type(e).__name__+': '+str(e),file=sys.stderr); sys.exit(1)
