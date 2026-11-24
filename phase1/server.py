"""Local-only Phase 1 TLS slice; no remote exec or arbitrary side effects."""
import argparse, base64, fcntl, hashlib, http.client, io, ipaddress, json, os, pathlib, secrets, socket, ssl, stat, sys, threading, time, urllib.parse, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from registry import Registry, Denied, Conflict, Busy, Limited, StorageError
from tls_transport import server_context, server_wrap
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from enrollment import raw_public, transcript, verify
from admin import Server as AdminServer
MAX_BODY=4096
MAX_STREAM=160*1024*1024
TRANSFER_DEADLINE=60

def encode(b): return base64.b64encode(b).decode('ascii')
def decode(s): return base64.b64decode(s,validate=True)
def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('duplicate JSON key')
        result[key]=value
    return result
class LimitedInput:
    def __init__(self,source,length): self.source=source; self.remaining=length
    def read(self,size=-1):
        if size<0: raise ValueError('unbounded read')
        if not self.remaining: return b''
        data=self.source.read(min(size,self.remaining)); self.remaining-=len(data); return data

class LimitedHeaders:
    def __init__(self,source,limit): self.source=source; self.remaining=limit
    def readline(self,size=-1):
        if self.remaining<=0: raise http.client.LineTooLong('headers')
        n=self.remaining+1 if size<0 else min(size,self.remaining+1)
        line=self.source.readline(n)
        if len(line)>self.remaining: raise http.client.LineTooLong('headers')
        self.remaining-=len(line); return line

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def setup(self):
        super().setup(); self.completed_auth=False; self.session_token=None; self.challenge_channel=None; self.challenge_issued=False; self.failed_auth=0; self.enroll_pending=None; self.enroll_started=False
    def finish(self):
        try: super().finish()
        finally:
            if self.session_token:
                with self.server.lock: self.server.sessions.pop(self.session_token,None)
            if self.challenge_channel is not None:
                for attempt in range(8):
                    try: self.server.registry.release(self.challenge_channel); break
                    except Busy: time.sleep(min(.025*(attempt+1),.2))
                    except StorageError: break  # TTL cleanup is the fallback
    def handle_expect_100(self):
        self.close_connection=True; self.send_error(417); return False
    def parse_request(self):
        original=self.rfile; self.rfile=LimitedHeaders(original,16384)
        try: parsed=super().parse_request()
        finally: self.rfile=original
        if not parsed: return False
        try:
            if len(self.headers.as_bytes())>16384: raise ValueError()
            for name in ('Host','Authorization','Content-Length','Transfer-Encoding','Content-Type','Connection','Expect','X-Transfer-ID','X-Chunk-Index'):
                if len(self.headers.get_all(name,[]))>1: raise ValueError()
            if self.request_version!='HTTP/1.1' or len(self.headers.get_all('Host',[]))!=1: raise ValueError()
            host=self.headers.get('Host','')
            if not host or len(host)>255 or any(c.isspace() or c in '/\\' for c in host): raise ValueError()
            if self.headers.get('Transfer-Encoding') is not None or self.headers.get('Expect') is not None: raise ValueError()
            length=self.headers.get('Content-Length')
            stream=self.command=='POST' and self.path in ('/v1/transfer/upload-stream','/v1/resume/chunk')
            limit=(256*1024 if self.path=='/v1/resume/chunk' else MAX_STREAM) if stream else MAX_BODY
            if length is not None and (not length.isascii() or not length.isdigit() or len(length)>9 or int(length)>limit): raise ValueError()
            if self.command=='GET' and length not in (None,'0'): raise ValueError()
            if self.command=='POST' and (length is None or self.headers.get('Content-Type','').lower()!=('application/octet-stream' if stream else 'application/json')): raise ValueError()
            if self.command not in ('GET','POST'): raise ValueError()
        except (ValueError,TypeError):
            self.close_connection=True; self.send_error(400); return False
        return True
    def log_message(self, format, *args): pass
    def respond(self,code,data):
        body=json.dumps(data,separators=(',',':')).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def channel(self):
        val=self.connection.exporter()
        if not val: raise Denied()
        return hashlib.sha256(val).digest()
    def ident(self,data):
        owner=data.get('owner'); device=data.get('device')
        if not all(isinstance(x,str) and 1<=len(x)<=64 and x.isascii() and all(c.isalnum() or c in '_-' for c in x) for x in (owner,device)): raise ValueError()
        return owner,device
    def body(self):
        if self.headers.get('Transfer-Encoding') is not None: raise ValueError()
        length=int(self.headers.get('Content-Length','-1'))
        if not 0<=length<=MAX_BODY: raise ValueError()
        raw=self.rfile.read(length)
        if len(raw)!=length: raise ValueError()
        obj=json.loads(raw,object_pairs_hook=unique_object)
        if not isinstance(obj,dict): raise ValueError()
        return obj
    def session(self):
        authorization=self.headers.get('Authorization','')
        if not authorization.startswith('Bearer '): raise Denied()
        token=authorization[7:]; channel=self.channel(); now=time.monotonic()
        with self.server.lock:
            info=self.server.sessions.get(token)
            if not info or info[2]!=channel or info[3]<=now: raise Denied()
            owner,device=info[:2]
        if not self.server.registry.enabled(owner,device): raise Denied()
        return owner,device
    def upload_stream(self):
        self.close_connection=True
        if self.server.transfers is None or self.server.transfer_root is None: raise Denied()
        owner,device=self.session(); tid=self.headers.get('X-Transfer-ID',''); length=int(self.headers['Content-Length'])
        if str(uuid.UUID(tid))!=tid or not 1<=length<=MAX_STREAM: raise ValueError()
        if not self.server.upload_slots.acquire(False): raise Limited()
        try:
            self.connection.deadline.extend_once()
            from transfer_crypto import context
            from transfer_ingest import receive
            from transfer_stream import InvalidEnvelope
            from transfer_compress import InvalidCompressed
            from transfer_archive import InvalidArchive
            key=self.server.transfers.get_key(owner,device,tid,'upload')
            binding=context(self.server.identity,owner,device,tid,'upload')
            try:
                space=os.statvfs(self.server.transfer_root)
                if space.f_bavail*space.f_frsize<512*1024*1024: raise StorageError('insufficient receive storage')
                result=receive(LimitedInput(self.rfile,length),self.server.transfer_root,tid,key,binding,publish=lambda commit:self.server.transfers.publish_if_authorized(owner,device,tid,commit),archive_limit=128*1024*1024)
            except (InvalidEnvelope,InvalidCompressed,InvalidArchive) as e: raise ValueError('invalid encrypted archive') from e
            except FileExistsError as e: raise Conflict() from e
            except OSError as e: raise StorageError('receive failed') from e
            self.respond(200,{'status':'received',**result})
        finally: self.server.upload_slots.release()
    def resume_chunk(self):
        if self.server.resume is None: raise Denied()
        owner,device=self.session(); tid=self.headers.get('X-Transfer-ID',''); idx=self.headers.get('X-Chunk-Index',''); length=int(self.headers['Content-Length'])
        if not idx.isascii() or not idx.isdigit() or len(idx)>6 or not 1<=length<=256*1024: raise ValueError()
        if not self.server.upload_slots.acquire(False): raise Limited()
        try:
            raw=self.rfile.read(length)
            if len(raw)!=length: raise ValueError()
            from resume_store import Corrupt
            try: fresh=self.server.resume.put(owner,device,tid,int(idx),raw)
            except Corrupt as e: raise Conflict() from e
            self.respond(200,{'new':fresh})
        finally: self.server.upload_slots.release()
    def do_POST(self):
      try:
        self.server.check_storage(reserve=self.path in ('/v1/transfer/issue','/v1/transfer/upload','/v1/transfer/upload-stream','/v1/resume/begin','/v1/resume/chunk','/v1/resume/finish','/v1/packages/create','/v1/exec'))
        if self.path=='/v1/transfer/upload-stream': return self.upload_stream()
        if self.path=='/v1/resume/chunk': return self.resume_chunk()
        data=self.body(); channel=self.channel(); reg=self.server.registry
        if self.path=='/v1/enroll/challenge':
            if self.completed_auth or self.enroll_started or self.challenge_issued or set(data)!={'owner','device','edpub','xpub'}: raise Denied()
            owner,device=self.ident(data); edpub=decode(data['edpub']); xpub=decode(data['xpub'])
            if len(edpub)!=32 or len(xpub)!=32: raise ValueError()
            X25519PublicKey.from_public_bytes(xpub)
            ephemeral=X25519PrivateKey.generate(); nonce=secrets.token_bytes(32); epub=raw_public(ephemeral.public_key())
            self.enroll_started=True; self.enroll_pending=(owner,device,edpub,xpub,ephemeral,nonce,epub,channel)
            self.respond(200,{'nonce':encode(nonce),'epub':encode(epub)}); return
        if self.path=='/v1/enroll/complete':
            if set(data)!={'otp','signature','proof'} or self.enroll_pending is None: raise Denied()
            pending=self.enroll_pending; self.enroll_pending=None
            owner,device,edpub,xpub,ephemeral,nonce,epub,bound=pending
            otp=data['otp']; signature=decode(data['signature']); mac=decode(data['proof'])
            if not isinstance(otp,str) or len(otp)!=43 or not otp.isascii() or len(signature)!=64 or len(mac)!=32 or bound!=channel: raise Denied()
            msg=transcript(self.server.identity,channel,nonce,owner,device,edpub,xpub,epub,otp)
            if not verify(edpub,xpub,ephemeral,nonce,msg,signature,mac): raise Denied()
            reg.enroll(owner,device,edpub,xpub,otp); self.respond(200,{'status':'enrolled'}); return
        if self.path=='/v1/challenge':
            if set(data)!={'owner','device'}: raise ValueError()
            if self.completed_auth or self.challenge_issued or self.enroll_started: raise Denied()
            owner,device=self.ident(data); challenge=reg.issue(owner,device,channel); self.challenge_issued=True; self.challenge_channel=channel; self.respond(200,{'challenge':encode(challenge)}); return
        if self.path=='/v1/auth':
            if set(data)!={'owner','device','challenge','signature'}: raise ValueError()
            if self.completed_auth or self.enroll_started: raise Denied()
            owner,device=self.ident(data); challenge=decode(data['challenge']); signature=decode(data['signature'])
            if len(challenge)!=32 or len(signature)!=64: raise ValueError()
            reg.authenticate(owner,device,channel,challenge,self.server.identity,signature)
            token=secrets.token_urlsafe(32)
            with self.server.lock:
                now=time.monotonic(); self.server.sessions={k:v for k,v in self.server.sessions.items() if v[3]>now}
                if len(self.server.sessions)>=128: raise Limited()
                self.server.sessions[token]=(owner,device,channel,now+60)
            self.completed_auth=True; self.failed_auth=0; self.session_token=token
            self.respond(200,{'session':token}); return
        if self.path=='/v1/resume/begin':
            if set(data)!={'manifest'} or self.server.resume is None: raise Denied()
            owner,device=self.session(); manifest=data['manifest']
            if not isinstance(manifest,dict): raise ValueError()
            from transfer_crypto import context
            binding=context(self.server.identity,owner,device,manifest.get('transfer_id'),'upload')
            if not self.server.upload_slots.acquire(False): raise Limited()
            try: self.server.resume.begin(owner,device,manifest,binding); self.respond(200,{'status':'ready'}); return
            finally: self.server.upload_slots.release()
        if self.path=='/v1/resume/finish':
            if set(data)!={'id'} or self.server.resume is None: raise Denied()
            owner,device=self.session()
            from transfer_crypto import context
            from resume_store import Corrupt
            from transfer_stream import InvalidEnvelope
            from transfer_compress import InvalidCompressed
            from transfer_archive import InvalidArchive
            binding=context(self.server.identity,owner,device,data['id'],'upload')
            if not self.server.upload_slots.acquire(False): raise Limited()
            try:
                self.connection.deadline.extend_once()
                try: result=self.server.resume.finish(owner,device,data['id'],binding)
                except (Corrupt,InvalidEnvelope,InvalidCompressed,InvalidArchive) as e: raise Conflict() from e
                self.respond(200,result); return
            finally: self.server.upload_slots.release()
        if self.path=='/v1/transfer/issue':
            if self.server.transfers is None: raise Denied()
            owner,device=self.session()
            if set(data)=={'request_id','direction','ttl'} and data['direction']=='upload': value=self.server.transfers.issue(owner,device,data['request_id'],'upload',data['ttl'])
            elif set(data)=={'request_id','direction','ttl','package_id'} and data['direction']=='download' and self.server.packages is not None: value=self.server.transfers.issue_download(owner,device,data['request_id'],data['package_id'],data['ttl'])
            else: raise Denied()
            self.respond(200,{**value,'enc':encode(value['enc']),'wrapped':encode(value['wrapped'])}); return
        if self.path=='/v1/transfer/upload':
            if set(data)!={'id','data'} or self.server.transfers is None or self.server.transfer_root is None: raise Denied()
            owner,device=self.session(); blob=decode(data['data'])
            if not 1<=len(blob)<=2048: raise ValueError()
            if not self.server.upload_slots.acquire(False): raise Limited()
            try:
                from transfer_crypto import context
                from transfer_ingest import receive
                from transfer_stream import InvalidEnvelope
                from transfer_compress import InvalidCompressed
                from transfer_archive import InvalidArchive
                key=self.server.transfers.get_key(owner,device,data['id'],'upload')
                binding=context(self.server.identity,owner,device,data['id'],'upload')
                try:
                    result=receive(io.BytesIO(blob),self.server.transfer_root,data['id'],key,binding,publish=lambda commit:self.server.transfers.publish_if_authorized(owner,device,data['id'],commit),archive_limit=8*1024*1024)
                except (InvalidEnvelope,InvalidCompressed,InvalidArchive) as e: raise ValueError('invalid encrypted archive') from e
                except FileExistsError as e: raise Conflict() from e
                except OSError as e: raise StorageError('receive failed') from e
                self.respond(200,{'status':'received',**result}); return
            finally: self.server.upload_slots.release()
        if self.path=='/v1/packages/create':
            if set(data)!={'source_id','request_id'} or self.server.packages is None: raise Denied()
            owner,device=self.session()
            if not self.server.upload_slots.acquire(False): raise Limited()
            try:
                self.connection.deadline.extend_once()
                from transfer_archive import InvalidArchive
                try: result=self.server.packages.create(owner,device,data['source_id'],data['request_id'])
                except InvalidArchive as e: raise ValueError('invalid package source') from e
                except OSError as e: raise StorageError('package creation failed') from e
                self.respond(200,result); return
            finally: self.server.upload_slots.release()
        if self.path=='/v1/packages/retire':
            if set(data)!={'package_id'} or self.server.packages is None: raise Denied()
            owner,device=self.session()
            try: self.server.packages.retire(owner,device,data['package_id'])
            except OSError as e: raise StorageError('package retirement failed') from e
            self.respond(200,{'status':'retired'}); return
        if self.path=='/v1/transfer/cancel':
            if set(data)!={'id'} or self.server.transfers is None: raise Denied()
            owner,device=self.session(); self.server.transfers.cancel(owner,device,data['id'])
            if self.server.resume is not None:
                try: self.server.resume.cleanup_terminal()
                except Busy: pass  # Background maintenance retries cleanup.
            if self.server.packages is not None:
                try: self.server.packages.cleanup_download(data['id'])
                except OSError as e: raise StorageError('ciphertext cleanup failed') from e
            self.respond(200,{'status':'cancelled'}); return
        if self.path=='/v1/test':
            if set(data)!={'request_id','payload'}: raise ValueError()
            owner,device=self.session(); rid=data.get('request_id'); payload=data.get('payload')
            if not isinstance(rid,str) or str(uuid.UUID(rid))!=rid or not isinstance(payload,str) or len(payload)>512: raise ValueError()
            result=reg.execute(owner,rid,payload.encode('utf-8'),device); self.respond(200,{'request_id':rid,**result}); return
        if self.path=='/v1/exec':
            owner,device=self.session()
            if self.server.executor is None: raise Denied()
            if set(data)!={'request_id','workspace','argv','timeout_seconds'}: raise ValueError()
            request={'operation':'exec','workspace':data['workspace'],'argv':data['argv'],'timeout_seconds':data['timeout_seconds']}
            try: result=self.server.executor.submit(owner,device,data['request_id'],request)
            except OSError as e: raise StorageError('workspace unavailable') from e
            self.respond(200,{'request_id':data['request_id'],**result}); return
        if self.path=='/v1/exec/cancel':
            owner,device=self.session()
            if self.server.executor is None: raise Denied()
            if set(data)!={'request_id'} or not isinstance(data['request_id'],str) or str(uuid.UUID(data['request_id']))!=data['request_id']: raise ValueError()
            state=self.server.executor.cancel(owner,device,data['request_id']); self.respond(200,{'request_id':data['request_id'],'state':state}); return
        self.respond(404,{'error':'not_found'})
      except (ValueError,KeyError,TypeError,UnicodeError): self.close_connection=True; self.respond(400,{'error':'bad_request'})
      except Denied:
          if self.path=='/v1/auth':
              self.failed_auth+=1
              if self.failed_auth>=4: self.close_connection=True
          self.respond(403,{'error':'denied'})
      except Conflict: self.respond(409,{'error':'conflict'})
      except Limited: self.respond(429,{'error':'limited'})
      except Busy: self.respond(503,{'error':'busy'})
      except StorageError: self.close_connection=True; self.respond(503,{'error':'storage_unavailable'})
      except OSError: self.close_connection=True; self.respond(503,{'error':'storage_unavailable'})
    def do_GET(self):
      try:
        if self.path=='/v1/health':
            self.server.check_storage()
            value=self.headers.get('X-Request-ID',''); rid=str(uuid.UUID(value))
            if rid!=value: raise ValueError()
            self.respond(200,{'request_id':rid,'status':'ok','protocol':'cs/1'}); return
        self.server.check_storage(reserve=False)
        url=urllib.parse.urlsplit(self.path)
        if url.path=='/v1/resume/download-meta':
            if self.server.resume_download is None: raise Denied()
            owner,device=self.session(); params=urllib.parse.parse_qs(url.query,strict_parsing=True)
            if set(params)!={'id'} or len(params['id'])!=1: raise ValueError()
            if not self.server.upload_slots.acquire(False): raise Limited()
            try:
                self.connection.deadline.extend_once()
                from resume_store import Corrupt
                try: result=self.server.resume_download.meta(owner,device,params['id'][0])
                except Corrupt as e: raise Conflict() from e
                self.respond(200,result); return
            finally: self.server.upload_slots.release()
        if url.path=='/v1/resume/download-index':
            if self.server.resume_download is None: raise Denied()
            owner,device=self.session(); params=urllib.parse.parse_qs(url.query,strict_parsing=True)
            if set(params)!={'id','cursor'} or len(params['id'])!=1 or len(params['cursor'])!=1 or not params['cursor'][0].isascii() or not params['cursor'][0].isdigit() or len(params['cursor'][0])>6: raise ValueError()
            self.respond(200,self.server.resume_download.index(owner,device,params['id'][0],int(params['cursor'][0]))); return
        if url.path=='/v1/resume/download-chunk':
            if self.server.resume_download is None: raise Denied()
            owner,device=self.session(); params=urllib.parse.parse_qs(url.query,strict_parsing=True)
            if set(params)!={'id','index'} or len(params['id'])!=1 or len(params['index'])!=1 or not params['index'][0].isascii() or not params['index'][0].isdigit() or len(params['index'][0])>6: raise ValueError()
            if not self.server.upload_slots.acquire(False): raise Limited()
            try:
                from resume_store import Corrupt
                try: data,digest=self.server.resume_download.chunk(owner,device,params['id'][0],int(params['index'][0]))
                except Corrupt as e: raise Conflict() from e
                self.send_response(200); self.send_header('Content-Type','application/octet-stream'); self.send_header('Content-Length',str(len(data))); self.send_header('X-Chunk-SHA256',digest); self.end_headers(); self.wfile.write(data); return
            finally: self.server.upload_slots.release()
        if url.path=='/v1/resume/status':
            if self.server.resume is None: raise Denied()
            owner,device=self.session(); params=urllib.parse.parse_qs(url.query,strict_parsing=True)
            if set(params)!={'id','cursor'} or len(params['id'])!=1 or len(params['cursor'])!=1 or not params['cursor'][0].isascii() or not params['cursor'][0].isdigit() or len(params['cursor'][0])>6: raise ValueError()
            cursor=int(params['cursor'][0]); tid=params['id'][0]
            if not self.server.upload_slots.acquire(False): raise Limited()
            try:
                if cursor==0: self.connection.deadline.extend_once()
                from resume_store import Corrupt,NotFound
                try: status=self.server.resume.reconcile(owner,device,tid) if cursor==0 else self.server.resume.status(owner,device,tid)
                except NotFound: self.respond(404,{'error':'not_found'}); return
                except Corrupt as e: raise Conflict() from e
                entries=[c for c in status['chunks'] if c['index']>=cursor][:16]
                next_cursor=entries[-1]['index']+1 if len(entries)==16 else None
                self.respond(200,{'manifest':status['manifest'],'state':status['state'],'chunks':entries,'next':next_cursor}); return
            finally: self.server.upload_slots.release()
        if url.path=='/v1/transfer/download':
            self.close_connection=True
            if self.server.packages is None or self.server.transfers is None: raise Denied()
            owner,device=self.session(); params=urllib.parse.parse_qs(url.query,strict_parsing=True)
            if set(params)!={'id'} or len(params['id'])!=1: raise ValueError()
            tid=params['id'][0]
            if not self.server.upload_slots.acquire(False): raise Limited()
            try:
                self.connection.deadline.extend_once()
                try: fd,size,package_id=self.server.packages.prepare_download(self.server.transfers,owner,device,tid)
                except ValueError as e: raise StorageError('invalid outgoing package') from e
                except OSError as e: raise StorageError('download unavailable') from e
                with os.fdopen(fd,'rb') as source:
                    self.send_response(200); self.send_header('Content-Type','application/octet-stream'); self.send_header('Content-Length',str(size)); self.send_header('X-Package-ID',package_id); self.end_headers()
                    while True:
                        try: self.server.transfers.download_info(owner,device,tid)
                        except (Denied,Busy,StorageError): return
                        block=source.read(65536)
                        if not block: break
                        self.wfile.write(block)
                return
            finally: self.server.upload_slots.release()
        if url.path=='/v1/packages':
            if url.query or self.server.packages is None: raise Denied()
            owner,device=self.session(); self.respond(200,{'packages':self.server.packages.list(owner,device)}); return
        if url.path=='/v1/packages/result':
            if self.server.packages is None: raise Denied()
            owner,device=self.session(); params=urllib.parse.parse_qs(url.query,strict_parsing=True)
            if set(params)!={'id'} or len(params['id'])!=1: raise ValueError()
            result=self.server.packages.lookup_request(owner,device,params['id'][0])
            if result is None: self.respond(404,{'error':'not_found'})
            else: self.respond(200,result)
            return
        if url.path=='/v1/transfer/upload-result':
            if self.server.transfers is None or self.server.transfer_root is None: raise Denied()
            owner,device=self.session(); params=urllib.parse.parse_qs(url.query,strict_parsing=True)
            if set(params)!={'id'} or len(params['id'])!=1: raise ValueError()
            tid=params['id'][0]
            if str(uuid.UUID(tid))!=tid: raise ValueError()
            def inspect():
                fd=os.open(self.server.transfer_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:
                    st=os.fstat(fd)
                    if st.st_uid!=os.geteuid() or st.st_mode & 0o077: raise StorageError('unsafe receive root')
                    try: item=os.stat(tid,dir_fd=fd,follow_symlinks=False)
                    except FileNotFoundError: return False
                    if not stat.S_ISDIR(item.st_mode) or item.st_uid!=os.geteuid(): raise StorageError('invalid published entry')
                    return True
                finally: os.close(fd)
            result=[]
            try: self.server.transfers.publish_if_authorized(owner,device,tid,lambda:result.append(inspect()))
            except OSError as e: raise StorageError('receive unavailable') from e
            if result[0]: self.respond(200,{'id':tid,'status':'received'})
            else: self.respond(404,{'error':'not_found'})
            return
        if url.path=='/v1/transfer/result':
            if self.server.transfers is None: raise Denied()
            owner,device=self.session(); params=urllib.parse.parse_qs(url.query,strict_parsing=True)
            if set(params)!={'id'} or len(params['id'])!=1: raise ValueError()
            value=self.server.transfers.lookup(owner,device,params['id'][0])
            if value is None: self.respond(404,{'error':'not_found'})
            else: self.respond(200,{**value,'enc':encode(value['enc']),'wrapped':encode(value['wrapped'])})
            return
        if url.path=='/v1/exec/result':
            owner,device=self.session()
            params=urllib.parse.parse_qs(url.query,strict_parsing=True)
            if set(params)!={'id'} or len(params['id'])!=1 or str(uuid.UUID(params['id'][0]))!=params['id'][0]: raise ValueError()
            from exec_journal import ExecJournal
            rid=params['id'][0]; result=ExecJournal(self.server.registry).result(owner,device,rid)
            if result is None: self.respond(404,{'error':'not_found'})
            else: self.respond(200,{'request_id':rid,**result})
            return
        if url.path!='/v1/result': self.respond(404,{'error':'not_found'}); return
        owner,device=self.session(); params=urllib.parse.parse_qs(url.query,strict_parsing=True); rid=params['id'][0]
        if len(params)!=1 or len(params['id'])!=1 or str(uuid.UUID(rid))!=rid: raise ValueError()
        result=self.server.registry.result(owner,rid,device)
        if result is None: self.respond(404,{'error':'not_found'})
        else: self.respond(200,{'request_id':rid,**result})
      except (ValueError,KeyError): self.respond(400,{'error':'bad_request'})
      except Denied: self.respond(403,{'error':'denied'})
      except Conflict: self.respond(409,{'error':'conflict'})
      except Limited: self.respond(429,{'error':'limited'})
      except Busy: self.respond(503,{'error':'busy'})
      except StorageError: self.respond(503,{'error':'storage_unavailable'})

class ConnectionDeadline:
    """One absolute extension, only after authorization and resource admission."""
    def __init__(self,transport,seconds):
        self.transport=transport; self.lock=threading.Lock(); self.timer=None; self.generation=0; self.closed=False; self.extended=False
        with self.lock: self._arm(seconds)
    def _arm(self,seconds):
        self.generation+=1; generation=self.generation
        if self.timer: self.timer.cancel()
        self.timer=threading.Timer(seconds,self._expire,args=(generation,)); self.timer.daemon=True; self.timer.start()
    def _expire(self,generation):
        with self.lock:
            if self.closed or generation!=self.generation: return
            self.closed=True
        try: self.transport.shutdown(socket.SHUT_RDWR)
        except OSError: pass
    def extend_once(self,seconds=TRANSFER_DEADLINE):
        with self.lock:
            if self.closed: raise Denied()
            if not self.extended: self.extended=True; self._arm(seconds)
    def cancel(self):
        with self.lock:
            self.closed=True; self.generation+=1
            if self.timer: self.timer.cancel()

class BoundedServer(ThreadingMixIn, HTTPServer):
    daemon_threads=True; request_queue_size=16
    def __init__(self,address,context,registry,identity,max_clients=16,timeout=3,deadline=6):
        self.context=context; self.registry=registry; self.identity=identity; self.transfers=None; self.transfer_root=None; self.packages=None; self.resume=None; self.resume_download=None; self.executor=None; self.storage_paths=None; self.storage_capacity_mib=None; self.upload_slots=threading.BoundedSemaphore(1); self.sessions={}; self.lock=threading.Lock(); self.slots=threading.BoundedSemaphore(max_clients); self.timeout=timeout; self.deadline=deadline
        super().__init__(address,Handler)
    def check_storage(self,reserve=True):
        if self.storage_paths is None: raise StorageError('storage boundary unavailable')
        from storage_guard import verify_bounded_filesystem
        try: verify_bounded_filesystem(self.storage_paths,self.storage_capacity_mib,512*1024*1024 if reserve else 0)
        except (OSError,ValueError) as e: raise StorageError('storage boundary or reserve unavailable') from e
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False): self.shutdown_request(request); return
        try: super().process_request(request,client_address)
        except BaseException: self.slots.release(); raise
    def process_request_thread(self,request,client_address):
        wrapped=None; deadline=None
        try:
            request.settimeout(self.timeout); wrapped=server_wrap(self.context,request)
            deadline=ConnectionDeadline(wrapped,self.deadline); wrapped.deadline=deadline
            wrapped.handshake(); self.finish_request(wrapped,client_address)
        except (OSError,ssl.SSLError): pass
        finally:
            if deadline: deadline.cancel()
            self.shutdown_request(wrapped if wrapped else request); self.slots.release()

def main():
    p=argparse.ArgumentParser(); p.add_argument('--cert',required=True); p.add_argument('--key',required=True); p.add_argument('--db',required=True); p.add_argument('--port',type=int,default=0); p.add_argument('--listen',default='127.0.0.1'); p.add_argument('--admin-socket'); p.add_argument('--transfer-master'); p.add_argument('--transfer-root'); p.add_argument('--package-root'); p.add_argument('--resume-root'); p.add_argument('--exec-root'); p.add_argument('--exec-policy'); p.add_argument('--pending-upload-mib',type=int,default=384); p.add_argument('--audit-retention-days',type=int,default=90); p.add_argument('--audit-max-records',type=int,default=100000); p.add_argument('--exec-result-retention-days',type=int,default=90); p.add_argument('--storage-capacity-mib',type=int); a=p.parse_args()
    try: a.listen=str(ipaddress.IPv4Address(a.listen))
    except ipaddress.AddressValueError: raise SystemExit('invalid IPv4 listen address')
    if not 1<=a.pending_upload_mib<=4096: raise SystemExit('invalid upload reservation limit')
    if not 1<=a.audit_retention_days<=3650 or not 100<=a.audit_max_records<=1000000 or not 1<=a.exec_result_retention_days<=3650: raise SystemExit('invalid retention policy')
    if os.geteuid()==0: raise SystemExit('refusing to run as root')
    if a.storage_capacity_mib is None: raise SystemExit('storage_capacity_mib is required')
    from storage_guard import verify_bounded_filesystem
    paths=[str(pathlib.Path(a.db).parent)]+[x for x in (a.transfer_root,a.package_root,a.resume_root,a.exec_root) if x]
    if a.admin_socket: paths.append(str(pathlib.Path(a.admin_socket).parent))
    verify_bounded_filesystem(paths,a.storage_capacity_mib)
    st=os.lstat(a.db)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077: raise SystemExit('registry must be a private regular file owned by the server user')
    context=server_context(a.cert,a.key)
    with open(a.cert,encoding='ascii') as f: identity=hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).digest()
    reg=Registry(a.db); reg.upgrade(); server=BoundedServer((a.listen,a.port),context,reg,identity); server.storage_paths=paths; server.storage_capacity_mib=a.storage_capacity_mib
    if a.transfer_master:
        fd=os.open(a.transfer_master,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077: raise ValueError('transfer master must be a private owned regular file')
            master=os.read(fd,33)
            if len(master)!=32: raise ValueError('transfer master must be 32 bytes')
        finally: os.close(fd)
        from transfer_store import TransferStore
        server.transfers=TransferStore(reg,master,identity); server.transfers.initialize()
    if a.transfer_root:
        if server.transfers is None: raise ValueError('transfer root requires master')
        fd=os.open(a.transfer_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            st=os.fstat(fd)
            if st.st_uid!=os.geteuid() or st.st_mode & 0o077: raise ValueError('transfer root must be private and owned')
        finally: os.close(fd)
        server.transfer_root=a.transfer_root
    package_lock=None
    if a.package_root:
        if server.transfers is None or server.transfer_root is None: raise ValueError('package root requires transfer master and receive root')
        from outgoing import Packages, _private_root
        fd=_private_root(a.package_root)
        try:
            package_lock=os.open('.cs-service.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=fd)
            st=os.fstat(package_lock)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077: raise ValueError('unsafe package service lock')
            fcntl.flock(package_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally: os.close(fd)
        server.packages=Packages(reg,a.package_root,server.transfer_root); server.packages.initialize()
    if a.resume_root:
        if server.transfers is None or server.transfer_root is None: raise ValueError('resume root requires transfer master and receive root')
        from resume_store import ResumeStore
        server.resume=ResumeStore(reg,server.transfers,a.resume_root,server.transfer_root,a.pending_upload_mib*1024*1024)
        fd=server.resume._root(); os.close(fd); server.resume.initialize(); server.resume.reconcile_all()
        if server.packages is not None:
            from resume_download import ResumeDownload
            server.resume_download=ResumeDownload(reg,server.transfers,server.packages); server.resume_download.initialize()
            server.packages.reconcile_download_staging()
    if a.exec_root:
        controller=None
        try:
            root=pathlib.Path(a.exec_root).resolve(strict=True)
            for value in (a.cert,a.key,a.db,a.transfer_master,a.transfer_root,a.package_root,a.resume_root,a.admin_socket,a.exec_policy):
                if value:
                    sensitive=pathlib.Path(value).resolve()
                    if sensitive==root or sensitive.is_relative_to(root) or root.is_relative_to(sensitive) or sensitive.is_relative_to(pathlib.Path('/usr')): raise ValueError('execution root overlaps a protected path')
            from exec_controller import ExecController
            from deployment_policy import load
            policy=load(a.exec_policy) if a.exec_policy else None
            controller=ExecController(reg,root,policy); controller.preflight(); server.executor=controller
        except Exception as e:
            if controller is not None: controller.close()
            print('exec disabled: '+type(e).__name__,file=sys.stderr,flush=True)
    maintenance_stop=threading.Event(); maintenance=None
    def maintain():
        while not maintenance_stop.wait(60):
            try:
                server.check_storage(reserve=False)
                if server.transfers is not None:
                    if server.packages is None: server.transfers.cleanup()
                    else: server.packages.cleanup_expired(server.transfers)
                    if server.resume is not None: server.resume.cleanup_terminal()
                    if server.resume_download is not None: server.resume_download.cleanup_terminal()
                reg.prune_audit(a.audit_retention_days,a.audit_max_records)
                from exec_journal import ExecJournal
                ExecJournal(reg).prune_results(a.exec_result_retention_days)
            except Exception as e:
                print('maintenance failed: '+type(e).__name__,file=sys.stderr,flush=True)
    maintenance=threading.Thread(target=maintain,daemon=True); maintenance.start()
    admin=None
    if a.admin_socket:
        admin=AdminServer(a.admin_socket,reg,lambda:server.check_storage(reserve=False)); threading.Thread(target=admin.serve_forever,daemon=True).start()
    try:
        print(server.server_port,flush=True); server.serve_forever()
    finally:
        maintenance_stop.set()
        if maintenance: maintenance.join(timeout=2)
        server.server_close()
        if admin: admin.shutdown(); admin.server_close()
        if server.executor is not None: server.executor.close()
        if package_lock is not None: os.close(package_lock)
if __name__=='__main__': main()
