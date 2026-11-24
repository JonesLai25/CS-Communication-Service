"""Route installed Linux Client commands without invoking a shell."""
import os,pathlib,sys
from install_runtime import hold

def main():
 root=pathlib.Path(__file__).resolve().parents[3]; hold(root)
 if len(sys.argv)<2 or sys.argv[1] not in ('enroll','exec','transfer','resume','cleanup'): raise SystemExit('usage: cs-client enroll|exec|transfer|resume|cleanup [options]')
 name={'enroll':'enroll_cli.py','exec':'exec_cli.py','transfer':'transfer_cli.py','resume':'resume_cli.py','cleanup':'cleanup_cli.py'}[sys.argv[1]]
 os.execv(sys.executable,[sys.executable,'-B',str(pathlib.Path(__file__).resolve().with_name(name)),*sys.argv[2:]])
if __name__=='__main__': main()
