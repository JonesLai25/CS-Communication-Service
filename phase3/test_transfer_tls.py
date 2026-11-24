import hashlib,io,os,pathlib,select,subprocess,sys,tempfile,time,unittest,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'phase1'))
from client import AuthenticatedClient,AuthorizationError,UnknownOutcome
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from registry import Registry
from transfer_crypto import open_envelope, context
from transfer_archive import pack,unpack
from transfer_compress import compress,decompress
from transfer_stream import encrypt,decrypt
P=pathlib.Path(__file__).resolve().parents[1]/'phase1'
class TLSIssue(unittest.TestCase):
 def test_authorized_issue_and_reconnect(self):
  with tempfile.TemporaryDirectory() as d:
   cert=d+'/cert'; tlskey=d+'/tlskey'; master=d+'/master'; db=d+'/db'; root=d+'/received'; os.mkdir(root,0o700); packages=d+'/packages'; os.mkdir(packages,0o700); r=Registry(db); r.initialize(); r.add_user('alice')
   ed=Ed25519PrivateKey.generate(); x=X25519PrivateKey.generate(); raw=lambda k:k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
   otp=r.create_otp('alice',300); r.enroll('alice','device',raw(ed.public_key()),raw(x.public_key()),otp)
   r.add_user('bob'); bob_ed=Ed25519PrivateKey.generate(); bob_x=X25519PrivateKey.generate(); otp=r.create_otp('bob',300); r.enroll('bob','other',raw(bob_ed.public_key()),raw(bob_x.public_key()),otp)
   with open(master,'wb') as f: f.write(os.urandom(32))
   os.chmod(master,0o600)
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',tlskey,'-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   proc=subprocess.Popen([sys.executable,str(P/'server.py'),'--storage-capacity-mib','1048576','--cert',cert,'--key',tlskey,'--db',db,'--transfer-master',master,'--transfer-root',root,'--package-root',packages],stdout=subprocess.PIPE,text=True)
   try:
    if not select.select([proc.stdout],[],[],5)[0]: self.fail('startup timeout')
    port=int(proc.stdout.readline()); rid=str(uuid.uuid4()); c=AuthenticatedClient('localhost',port,cert,'alice','device',ed)
    try:
     with self.assertRaises(AuthorizationError): c.transfer_issue(rid,'upload',300)
     c.authenticate()
     with self.assertRaises(AuthorizationError): c.transfer_issue(str(uuid.uuid4()),'download',300)
     entry=c.transfer_issue(rid,'upload',300); identity=hashlib.sha256(c.conn.sock.getpeercert(binary_form=True)).digest()
     secret=open_envelope(entry['enc'],entry['wrapped'],x,identity,'alice','device',entry['id'],'upload'); self.assertEqual(len(secret),32)
     source=pathlib.Path(d)/'source'; source.mkdir(mode=0o700); (source/'hello').write_text('through TLS')
     tar=io.BytesIO(); pack(str(source),tar); packed=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),packed); cipher=io.BytesIO()
     encrypt(io.BytesIO(packed.getvalue()),cipher,secret,context(identity,'alice','device',entry['id'],'upload'))
     self.assertEqual(c.transfer_upload_small(entry['id'],cipher.getvalue()),{'status':'received','files_and_directories':1,'bytes':11})
     self.assertEqual((pathlib.Path(root)/entry['id']/'hello').read_text(),'through TLS')
     package_request=str(uuid.uuid4()); package=c.package_create(entry['id'],package_request); self.assertNotEqual(package['package_id'],entry['id']); self.assertEqual(c.package_result(package_request),package)
     bob=AuthenticatedClient('localhost',port,cert,'bob','other',bob_ed)
     try:
      bob.authenticate()
      with self.assertRaises(AuthorizationError): bob.transfer_issue(str(uuid.uuid4()),'download',300,package_id=package['package_id'])
      self.assertIsNone(bob.package_result(package_request))
     finally: bob.close()
     download=c.transfer_issue(str(uuid.uuid4()),'download',300,package_id=package['package_id'])
     downkey=open_envelope(download['enc'],download['wrapped'],x,identity,'alice','device',download['id'],'download',package['package_id']); self.assertEqual(len(downkey),32)
     self.assertEqual(c.call('POST','/v1/packages/retire',{'package_id':package['package_id']})[0],409)
     downloaded=io.BytesIO(); self.assertGreater(c.transfer_download_stream(download['id'],package['package_id'],downloaded),0)
     compressed=io.BytesIO(); decrypt(io.BytesIO(downloaded.getvalue()),compressed,downkey,context(identity,'alice','device',download['id'],'download',package['package_id']))
     archive=io.BytesIO(); decompress(io.BytesIO(compressed.getvalue()),archive); restore=pathlib.Path(d)/'restore'; restore.mkdir(mode=0o700); unpack(io.BytesIO(archive.getvalue()),str(restore)); self.assertEqual((restore/'hello').read_text(),'through TLS')
     c=AuthenticatedClient('localhost',port,cert,'alice','device',ed); c.authenticate()
     replayed=io.BytesIO(); c.transfer_download_stream(download['id'],package['package_id'],replayed); self.assertEqual(replayed.getvalue(),downloaded.getvalue())
     c=AuthenticatedClient('localhost',port,cert,'alice','device',ed); c.authenticate()
     self.assertEqual(c.call('POST','/v1/transfer/cancel',{'id':download['id']})[0],200)
     self.assertFalse((pathlib.Path(packages)/('download-'+download['id'])).exists())
     self.assertEqual(c.call('POST','/v1/packages/retire',{'package_id':package['package_id']})[0],200)
     # Simulate a response lost after successful server publication.
     lost=c.transfer_issue(str(uuid.uuid4()),'upload',300); lostkey=open_envelope(lost['enc'],lost['wrapped'],x,identity,'alice','device',lost['id'],'upload')
     lostcipher=io.BytesIO(); encrypt(io.BytesIO(packed.getvalue()),lostcipher,lostkey,context(identity,'alice','device',lost['id'],'upload'))
     original=c.conn.getresponse
     def drop():
      response=original(); response.read(); raise ConnectionResetError('simulated response loss after commit')
     c.conn.getresponse=drop
     with self.assertRaises(UnknownOutcome): c.transfer_upload_small(lost['id'],lostcipher.getvalue())

    finally: c.close()
    c=AuthenticatedClient('localhost',port,cert,'alice','device',ed)
    try:
     c.authenticate(); self.assertEqual(c.transfer_result(rid),entry); self.assertEqual(c.transfer_upload_result(entry['id']),{'id':entry['id'],'status':'received'}); self.assertEqual(c.transfer_upload_result(lost['id']),{'id':lost['id'],'status':'received'})
     status,result=c.call('POST','/v1/transfer/cancel',{'id':entry['id']}); self.assertEqual((status,result),(200,{'status':'cancelled'})); self.assertIsNone(c.transfer_result(rid))
    finally: c.close()
    # Larger encrypted archive travels as a bounded binary request, not JSON.
    c=AuthenticatedClient('localhost',port,cert,'alice','device',ed)
    try:
     c.authenticate(); big=c.transfer_issue(str(uuid.uuid4()),'upload',300)
     bigkey=open_envelope(big['enc'],big['wrapped'],x,identity,'alice','device',big['id'],'upload')
     payload=os.urandom(2*1024*1024); (source/'hello').write_bytes(payload)
     tar=io.BytesIO(); pack(str(source),tar); packed=io.BytesIO(); compress(io.BytesIO(tar.getvalue()),packed); cipher=io.BytesIO(); encrypt(io.BytesIO(packed.getvalue()),cipher,bigkey,context(identity,'alice','device',big['id'],'upload'))
     result=c.transfer_upload_stream(big['id'],io.BytesIO(cipher.getvalue()),len(cipher.getvalue()))
     self.assertEqual(result,{'status':'received','files_and_directories':1,'bytes':len(payload)})
     self.assertEqual((pathlib.Path(root)/big['id']/'hello').read_bytes(),payload)
    finally: c.close()
    c=AuthenticatedClient('localhost',port,cert,'alice','device',ed)
    try:
     c.authenticate(); self.assertEqual(c.transfer_upload_result(big['id']),{'id':big['id'],'status':'received'})
     bad=c.transfer_issue(str(uuid.uuid4()),'upload',300); badkey=open_envelope(bad['enc'],bad['wrapped'],x,identity,'alice','device',bad['id'],'upload')
     badcipher=io.BytesIO(); encrypt(io.BytesIO(packed.getvalue()),badcipher,badkey,context(identity,'alice','device',bad['id'],'upload'))
     rawbad=badcipher.getvalue(); rawbad=rawbad[:-1]+bytes([rawbad[-1]^1])
     with self.assertRaises(UnknownOutcome): c.transfer_upload_stream(bad['id'],io.BytesIO(rawbad),len(rawbad))
    finally: c.close()
    c=AuthenticatedClient('localhost',port,cert,'alice','device',ed)
    try:
     c.authenticate(); self.assertIsNone(c.transfer_upload_result(bad['id'])); self.assertFalse((pathlib.Path(root)/bad['id']).exists())
     interrupted=c.transfer_issue(str(uuid.uuid4()),'upload',300); interrupted_key=open_envelope(interrupted['enc'],interrupted['wrapped'],x,identity,'alice','device',interrupted['id'],'upload')
     partial=io.BytesIO(); encrypt(io.BytesIO(packed.getvalue()),partial,interrupted_key,context(identity,'alice','device',interrupted['id'],'upload')); contents=partial.getvalue()
     with self.assertRaises(UnknownOutcome): c.transfer_upload_stream(interrupted['id'],io.BytesIO(contents[:-1]),len(contents))
    finally: c.close()
    c=AuthenticatedClient('localhost',port,cert,'alice','device',ed)
    try: c.authenticate(); self.assertIsNone(c.transfer_upload_result(interrupted['id']))
    finally: c.close()
    deadline=time.monotonic()+5
    while any(p.name.startswith('.cs-incoming-') for p in pathlib.Path(root).iterdir()) and time.monotonic()<deadline: time.sleep(.02)
    self.assertFalse(any(p.name.startswith('.cs-incoming-') for p in pathlib.Path(root).iterdir()))
    self.assertFalse((pathlib.Path(root)/interrupted['id']).exists())
   finally:
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    proc.stdout.close()
if __name__=='__main__': unittest.main(verbosity=2)
