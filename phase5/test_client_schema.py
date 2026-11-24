import base64,pathlib,sys,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from client import AuthenticatedClient,ProtocolError,UnknownOutcome,AuthorizationError
class Responses(unittest.TestCase):
 def setUp(self): self.client=object.__new__(AuthenticatedClient); self.rid=str(uuid.uuid4())
 def test_result_strict_schema_and_bound(self):
  good={'request_id':self.rid,'state':'succeeded','exit_code':0,'stdout_b64':base64.b64encode(b'ok').decode(),'stderr_b64':''}
  self.client.call=lambda *a,**k:(200,good)
  self.assertEqual(self.client.exec_result(self.rid)['stdout'],b'ok')
  for bad in ({**good,'stdout_b64':'%%%URL'}, {**good,'extra':1}, {**good,'request_id':str(uuid.uuid4())}, {**good,'exit_code':True}, {**good,'stdout_b64':base64.b64encode(b'x'*2049).decode()}):
   self.client.call=lambda *a,_bad=bad,**k:(200,_bad)
   with self.assertRaises(ProtocolError): self.client.exec_result(self.rid)
 def test_submit_unknown_response_is_never_success(self):
  for status,data,error in ((200,{'request_id':self.rid,'new':1,'state':'queued'},UnknownOutcome),(403,{'error':'denied'},AuthorizationError),(503,{'error':'busy'},UnknownOutcome)):
   self.client.call=lambda *a,_s=status,_d=data,**k:(_s,_d)
   with self.assertRaises(error): self.client.exec_submit(self.rid,'alice',['/usr/bin/true'],3)
if __name__=='__main__': unittest.main(verbosity=2)
