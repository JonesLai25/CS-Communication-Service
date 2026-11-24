"""A child process for workspace publication crash boundaries; test data only."""
import pathlib,signal,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
import workspace_snapshot as snapshot
root=pathlib.Path(sys.argv[1]); checkpoint=sys.argv[2]; original=snapshot._marker
expected=snapshot.copy_tree(root/'workspace',root/'stage'); (root/'stage'/'item').write_text('after')
def inject(fd,name,record):
 if checkpoint=='after' and record['state']=='committed': print('AT_CHECKPOINT',flush=True); signal.pause()
 result=original(fd,name,record)
 if checkpoint=='before' and record['state']=='prepared': print('AT_CHECKPOINT',flush=True); signal.pause()
 return result
snapshot._marker=inject
snapshot.publish(root/'stage',root/'workspace',expected,'crashtest')
