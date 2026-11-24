"""TLS 1.3 verified local health request with bounded response validation."""
import argparse, http.client, json, re, socket, ssl, time, uuid
MAX_BODY=4096
class CSError(Exception): pass
class NetworkError(CSError): pass
class TLSError(CSError): pass
class AuthorizationError(CSError): pass
class ProtocolError(CSError): pass
class RemoteOperationError(CSError): pass
class TemporaryUnavailable(CSError): pass
class LocalStorageError(CSError): pass
class UnknownOutcome(CSError): pass

class _BoundedSource:
    def __init__(self,source,length,deadline): self.source=source; self.remaining=length; self.deadline=deadline
    def read(self,size):
        if time.monotonic()>=self.deadline: raise TimeoutError('upload deadline exceeded')
        if not self.remaining: return b''
        if not isinstance(size,int) or size<0: raise ValueError('invalid read size')
        data=self.source.read(min(size,self.remaining))
        if not isinstance(data,bytes) or len(data)>min(size,self.remaining): raise ValueError('invalid source')
        self.remaining-=len(data); return data

class TLSOnlyHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        raise OSError("TLS connection closed; create a new authenticated client")

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError("duplicate response key")
        result[key]=value
    return result

def validate_response(status,content_type,body,rid):
    if len(body)>MAX_BODY: raise ProtocolError('response too large')
    if status in (401,403): raise AuthorizationError('access denied')
    if status >= 500: raise RemoteOperationError('server error')
    if status!=200 or content_type.split(';',1)[0].strip().lower()!='application/json': raise ProtocolError('unexpected status or content type')
    try: data=json.loads(body)
    except (ValueError,UnicodeDecodeError) as e: raise ProtocolError('invalid JSON') from e
    if not isinstance(data,dict) or set(data)!={'request_id','status','protocol'} or data!={'request_id':rid,'status':'ok','protocol':'cs/1'}: raise ProtocolError('invalid schema or request ID')
    return data

def health(host,port,ca):
    ctx=ssl.create_default_context(cafile=ca); ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    rid=str(uuid.uuid4()); conn=http.client.HTTPSConnection(host,port,context=ctx,timeout=5)
    try:
        conn.request('GET','/v1/health',headers={'X-Request-ID':rid}); response=conn.getresponse()
        return validate_response(response.status,response.getheader('Content-Type',''),response.read(MAX_BODY+1),rid)
    except ssl.SSLError as e: raise TLSError('TLS validation or handshake failed') from e
    except http.client.HTTPException as e: raise ProtocolError('invalid HTTP response') from e
    except OSError as e: raise NetworkError('network transport error') from e
    finally: conn.close()
if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--host',default='localhost'); p.add_argument('--port',type=int,required=True); p.add_argument('--ca',required=True); a=p.parse_args(); print(json.dumps(health(a.host,a.port,a.ca)))

class AuthenticatedClient:
    """Each instance owns one TLS connection; never automatically resubmits test operations."""
    def __init__(self,host,port,ca,owner,device,key):
        self.owner=owner; self.device=device; self.key=key; self.token=None; self._host=host; self._port=port; self._ca=ca; self._authenticated_at=0
        from OpenSSL import SSL
        from tls_transport import client_wrap, TLSFailure
        self.conn=TLSOnlyHTTPConnection(host,port,timeout=5)
        try: raw=socket.create_connection((host,port),timeout=5)
        except OSError as e: raise NetworkError('connection failed') from e
        try: self.conn.sock=client_wrap(raw,host,ca)
        except (TLSFailure,SSL.Error,ssl.CertificateError) as e:
            raw.close(); raise TLSError('certificate or TLS validation failed') from e
        except BaseException:
            raw.close(); raise
    def close(self): self.token=None; self.conn.close()
    def call(self,method,path,data=None,raw_body=None,extra_headers=None):
        from tls_transport import TLSFailure
        headers={}
        if self.token: headers['Authorization']='Bearer '+self.token
        if raw_body is not None and data is not None: raise ValueError('ambiguous request body')
        body=raw_body if raw_body is not None else (None if data is None else json.dumps(data,separators=(',',':')).encode())
        if body is not None: headers['Content-Type']='application/octet-stream' if raw_body is not None else 'application/json'
        if extra_headers: headers.update(extra_headers)
        try:
            self.conn.request(method,path,body=body,headers=headers); response=self.conn.getresponse()
            lengths=response.headers.get_all('Content-Length',[]); types=response.headers.get_all('Content-Type',[])
            if len(lengths)!=1 or len(types)!=1 or response.headers.get_all('Transfer-Encoding',[]) or not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0])>5 or int(lengths[0])>MAX_BODY or types[0].split(';',1)[0].strip().lower()!='application/json':
                self.close(); raise ProtocolError('invalid response headers')
            raw=response.read(int(lengths[0])+1)
            if len(raw)!=int(lengths[0]): self.close(); raise ProtocolError('invalid response length')
        except (ssl.SSLError,TLSFailure) as e:
            if path in ('/v1/test','/v1/enroll/complete','/v1/transfer/issue','/v1/transfer/cancel','/v1/transfer/upload','/v1/packages/create','/v1/packages/retire','/v1/resume/begin','/v1/resume/chunk','/v1/resume/finish','/v1/exec','/v1/exec/cancel'): raise UnknownOutcome('retain request ID; reconnect and query') from e
            raise TLSError('TLS failure') from e
        except http.client.IncompleteRead as e:
            self.close()
            if path in ('/v1/test','/v1/enroll/complete','/v1/transfer/issue','/v1/transfer/cancel','/v1/transfer/upload','/v1/packages/create','/v1/packages/retire','/v1/resume/begin','/v1/resume/chunk','/v1/resume/finish','/v1/exec','/v1/exec/cancel'): raise UnknownOutcome('retain request ID; reconnect and query') from e
            raise ProtocolError('incomplete response') from e
        except http.client.RemoteDisconnected as e:
            self.close()
            if path in ('/v1/test','/v1/enroll/complete','/v1/transfer/issue','/v1/transfer/cancel','/v1/transfer/upload','/v1/packages/create','/v1/packages/retire','/v1/resume/begin','/v1/resume/chunk','/v1/resume/finish','/v1/exec','/v1/exec/cancel'): raise UnknownOutcome('retain request ID; reconnect and query') from e
            raise NetworkError('peer disconnected') from e
        except http.client.HTTPException as e:
            self.close()
            if path in ('/v1/test','/v1/enroll/complete','/v1/transfer/issue','/v1/transfer/cancel','/v1/transfer/upload','/v1/packages/create','/v1/packages/retire','/v1/resume/begin','/v1/resume/chunk','/v1/resume/finish','/v1/exec','/v1/exec/cancel'): raise UnknownOutcome('retain request ID; reconnect and query') from e
            raise ProtocolError('invalid HTTP response') from e
        except OSError as e:
            self.close()
            if path in ('/v1/test','/v1/enroll/complete','/v1/transfer/issue','/v1/transfer/cancel','/v1/transfer/upload','/v1/packages/create','/v1/packages/retire','/v1/resume/begin','/v1/resume/chunk','/v1/resume/finish','/v1/exec','/v1/exec/cancel'): raise UnknownOutcome('retain request ID; reconnect and query') from e
            raise NetworkError('network failure') from e
        if len(raw)>MAX_BODY: raise ProtocolError('response too large')
        try: value=json.loads(raw,object_pairs_hook=unique_object)
        except (ValueError,UnicodeDecodeError) as e:
            self.close(); raise ProtocolError('invalid JSON') from e
        if not isinstance(value,dict): self.close(); raise ProtocolError('response must be object')
        return response.status,value
    def authenticate(self):
        import base64,hashlib
        from registry import message
        status,value=self.call('POST','/v1/challenge',{'owner':self.owner,'device':self.device})
        if status in (401,403) and value=={'error':'denied'}: raise AuthorizationError('challenge denied')
        if status==429 or status>=500: raise RemoteOperationError('challenge unavailable')
        if status!=200 or set(value)!={'challenge'}: raise ProtocolError('invalid challenge response')
        try: challenge=base64.b64decode(value['challenge'],validate=True)
        except (ValueError,TypeError) as e: raise ProtocolError('invalid challenge') from e
        if len(challenge)!=32: raise ProtocolError('invalid challenge')
        binding=self.conn.sock.exporter()
        if not binding: raise TLSError('channel binding unavailable')
        channel=hashlib.sha256(binding).digest(); server=hashlib.sha256(self.conn.sock.getpeercert(binary_form=True)).digest()
        sig=self.key.sign(message(server,channel,challenge,self.owner,self.device))
        status,value=self.call('POST','/v1/auth',{'owner':self.owner,'device':self.device,'challenge':base64.b64encode(challenge).decode(),'signature':base64.b64encode(sig).decode()})
        if status in (401,403) and value=={'error':'denied'}: raise AuthorizationError('authentication denied')
        if status==429 or status>=500: raise RemoteOperationError('authentication unavailable')
        if status!=200 or set(value)!={'session'} or not isinstance(value['session'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',value['session']): raise ProtocolError('invalid authentication response')
        self.token=value['session']
        self._authenticated_at=time.monotonic()
    def exec_submit(self,request_id,workspace,argv,timeout_seconds):
        try: status,data=self.call('POST','/v1/exec',{'request_id':request_id,'workspace':workspace,'argv':argv,'timeout_seconds':timeout_seconds})
        except ProtocolError as e: raise UnknownOutcome('retain request ID; reconnect and query') from e
        if status==403: raise AuthorizationError('execution denied')
        if status==409: raise ProtocolError('request ID conflict')
        if status==429: raise TemporaryUnavailable('execution capacity reached')
        if status>=500: raise UnknownOutcome('retain request ID; reconnect and query')
        if status!=200 or set(data)!={'request_id','new','state'} or data['request_id']!=request_id or type(data['new']) is not bool or data['state'] not in ('queued','running','succeeded','failed','cancelled','timed_out','unknown','expired'): raise UnknownOutcome('invalid response; retain request ID and query')
        return data
    def exec_result(self,request_id):
        import base64,binascii
        status,data=self.call('GET','/v1/exec/result?id='+request_id)
        if status==404 and data=={'error':'not_found'}: return None
        if status==403: raise AuthorizationError('execution result denied')
        if status>=500: raise RemoteOperationError('execution result unavailable')
        if status!=200 or set(data)!={'request_id','state','exit_code','stdout_b64','stderr_b64'} or data['request_id']!=request_id or data['state'] not in ('queued','running','succeeded','failed','cancelled','timed_out','unknown','expired') or data['exit_code'] is not None and type(data['exit_code']) is not int: raise ProtocolError('invalid execution result')
        try:
            stdout=base64.b64decode(data['stdout_b64'],validate=True); stderr=base64.b64decode(data['stderr_b64'],validate=True)
        except (ValueError,TypeError,binascii.Error) as e: raise ProtocolError('invalid execution output') from e
        if len(stdout)+len(stderr)>2048: raise ProtocolError('execution output exceeds limit')
        return {'request_id':request_id,'state':data['state'],'exit_code':data['exit_code'],'stdout':stdout,'stderr':stderr}
    def exec_cancel(self,request_id):
        try: status,data=self.call('POST','/v1/exec/cancel',{'request_id':request_id})
        except ProtocolError as e: raise UnknownOutcome('retain request ID; reconnect and query') from e
        if status==403: raise AuthorizationError('execution cancellation denied')
        if status>=500: raise UnknownOutcome('retain request ID; reconnect and query')
        if status!=200 or set(data)!={'request_id','state'} or data['request_id']!=request_id or data['state'] not in ('queued','running','succeeded','failed','cancelled','timed_out','unknown','expired'): raise UnknownOutcome('invalid cancellation response; query request')
        return data
    def exec_wait(self,request_id,timeout=305):
        if type(timeout) not in (int,float) or not 0<timeout<=305: raise ValueError('invalid wait timeout')
        deadline=time.monotonic()+timeout; current=self; owned=False
        try:
            while time.monotonic()<deadline:
                if not current.token or time.monotonic()-current._authenticated_at>45:
                    if owned: current.close()
                    current=AuthenticatedClient(self._host,self._port,self._ca,self.owner,self.device,self.key); owned=True; current.authenticate()
                result=current.exec_result(request_id)
                if result is None: return None
                if result['state'] not in ('queued','running'): return result
                time.sleep(min(.25,max(0,deadline-time.monotonic())))
            raise UnknownOutcome('wait deadline; reconnect and query original request')
        finally:
            if owned: current.close()
    def submit(self,request_id,payload):
        try: status,data=self.call('POST','/v1/test',{'request_id':request_id,'payload':payload})
        except ProtocolError as e: raise UnknownOutcome('retain request ID; reconnect and query') from e
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('denied')
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('request ID content conflict')
        if status>=500: raise UnknownOutcome('retain request ID; reconnect and query')
        if status!=200 or set(data)!={'request_id','new','state','result'} or data['request_id']!=request_id or type(data['new']) is not bool or data['state']!='succeeded' or data['result']!='recorded': raise UnknownOutcome('invalid response; retain request ID and query')
        return data
    def result(self,request_id):
        status,data=self.call('GET','/v1/result?id='+request_id)
        if status==404 and data=={'error':'not_found'}: return None
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('denied')
        if status>=500: raise RemoteOperationError('query unavailable')
        if status!=200 or set(data)!={'request_id','state','result'} or data['request_id']!=request_id or data['state']!='succeeded' or data['result']!='recorded': raise ProtocolError('invalid result response')
        return data
    def _transfer_response(self,status,data,request_id):
        import base64
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('transfer denied')
        if status==404 and data=={'error':'not_found'}: return None
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('request ID conflict')
        if status>=500 or status==429: raise RemoteOperationError('transfer unavailable')
        if status!=200 or set(data) not in ({'id','direction','expires','enc','wrapped'},{'id','direction','expires','enc','wrapped','package_id'}): raise ProtocolError('invalid transfer response')
        try:
            if str(uuid.UUID(data['id']))!=data['id'] or data['direction'] not in ('upload','download') or type(data['expires']) is not int: raise ValueError()
            if data['direction']=='download' and (set(data)!={'id','direction','expires','enc','wrapped','package_id'} or str(uuid.UUID(data['package_id']))!=data['package_id']): raise ValueError()
            if data['direction']=='upload' and 'package_id' in data: raise ValueError()
            enc=base64.b64decode(data['enc'],validate=True); wrapped=base64.b64decode(data['wrapped'],validate=True)
        except (ValueError,TypeError,KeyError) as e: raise ProtocolError('invalid transfer response') from e
        if len(enc)!=32 or len(wrapped)!=48: raise ProtocolError('invalid transfer envelope')
        return {**data,'enc':enc,'wrapped':wrapped}
    def transfer_issue(self,request_id,direction,ttl=3600,package_id=None):
        payload={'request_id':request_id,'direction':direction,'ttl':ttl}
        if package_id is not None: payload['package_id']=package_id
        try: status,data=self.call('POST','/v1/transfer/issue',payload)
        except ProtocolError as e: raise UnknownOutcome('retain request ID and query transfer outcome') from e
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('request ID conflict')
        try:
            result=self._transfer_response(status,data,request_id)
            if result is None or result['direction']!=direction or (direction=='download' and result.get('package_id')!=package_id): raise ProtocolError('invalid issued direction')
            return result
        except (ProtocolError,RemoteOperationError) as e: raise UnknownOutcome('retain request ID and query transfer outcome') from e
    def transfer_result(self,request_id):
        status,data=self.call('GET','/v1/transfer/result?id='+request_id)
        return self._transfer_response(status,data,request_id)
    @staticmethod
    def _package_response(status,data):
        if status==404 and data=={'error':'not_found'}: return None
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('package denied')
        if status>=500 or status==429: raise RemoteOperationError('package unavailable')
        if status!=200 or set(data)!={'package_id','size','sha256'}: raise ProtocolError('invalid package response')
        try:
            if str(uuid.UUID(data['package_id']))!=data['package_id'] or type(data['size']) is not int or data['size']<0 or not isinstance(data['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',data['sha256']): raise ValueError()
        except (ValueError,TypeError) as e: raise ProtocolError('invalid package response') from e
        return data
    def package_create(self,source_id,request_id):
        sock=self.conn.sock
        if sock is None: raise NetworkError('connection closed')
        previous=sock.timeout; sock.timeout=60
        try:
            try: status,data=self.call('POST','/v1/packages/create',{'source_id':source_id,'request_id':request_id})
            except ProtocolError as e: raise UnknownOutcome('retain request ID and query package outcome') from e
        finally: sock.timeout=previous
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('request ID conflict')
        try:
            result=self._package_response(status,data)
            if result is None: raise ProtocolError('missing package')
            return result
        except (ProtocolError,RemoteOperationError) as e: raise UnknownOutcome('retain request ID and query package outcome') from e
    def package_result(self,request_id):
        status,data=self.call('GET','/v1/packages/result?id='+request_id)
        return self._package_response(status,data)
    def packages_list(self):
        status,data=self.call('GET','/v1/packages')
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('package access denied')
        if status>=500: raise RemoteOperationError('package list unavailable')
        if status!=200 or set(data)!={'packages'} or not isinstance(data['packages'],list) or len(data['packages'])>4: raise ProtocolError('invalid package list')
        packages=[self._package_response(200,item) for item in data['packages'] if isinstance(item,dict)]
        if len(packages)!=len(data['packages']) or len({p['package_id'] for p in packages})!=len(packages): raise ProtocolError('invalid package list')
        return packages
    def package_retire(self,package_id):
        try: status,data=self.call('POST','/v1/packages/retire',{'package_id':package_id})
        except ProtocolError as e: raise UnknownOutcome('package retirement outcome unknown') from e
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('package retirement denied')
        if status==409 and data=={'error':'conflict'}: raise RemoteOperationError('package has active downloads')
        if status!=200 or data!={'status':'retired'}: raise UnknownOutcome('package retirement outcome unknown')
        return True
    def resume_begin(self,manifest):
        try: status,data=self.call('POST','/v1/resume/begin',{'manifest':manifest})
        except ProtocolError as e: raise UnknownOutcome('query resume state before retry') from e
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('resume denied')
        if (status==429 and data=={'error':'limited'}) or (status==503 and data=={'error':'busy'}): raise TemporaryUnavailable('resume temporarily unavailable')
        if status==503 and data=={'error':'storage_unavailable'}: raise RemoteOperationError('resume storage unavailable')
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('resume manifest conflict')
        if status!=200 or data!={'status':'ready'}: raise UnknownOutcome('query resume state before retry')
    def resume_chunk(self,transfer_id,index,chunk):
        if type(index) is not int or index<0 or not isinstance(chunk,bytes) or not 1<=len(chunk)<=256*1024: raise ValueError('invalid resume chunk')
        try: status,data=self.call('POST','/v1/resume/chunk',raw_body=chunk,extra_headers={'X-Transfer-ID':transfer_id,'X-Chunk-Index':str(index)})
        except ProtocolError as e: raise UnknownOutcome('query resume state before retry') from e
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('resume denied')
        if (status==429 and data=={'error':'limited'}) or (status==503 and data=={'error':'busy'}): raise TemporaryUnavailable('resume temporarily unavailable')
        if status==503 and data=={'error':'storage_unavailable'}: raise RemoteOperationError('resume storage unavailable')
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('resume chunk conflict')
        if status!=200 or set(data)!={'new'} or type(data['new']) is not bool: raise UnknownOutcome('query resume state before retry')
        return data['new']
    def resume_status(self,transfer_id,cursor=0):
        sock=self.conn.sock
        if sock is None: raise NetworkError('connection closed')
        previous=sock.timeout
        if cursor==0: sock.timeout=60
        try: status,data=self.call('GET','/v1/resume/status?id='+transfer_id+'&cursor='+str(cursor))
        finally: sock.timeout=previous
        if status==404 and data=={'error':'not_found'}: return None
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('resume denied')
        if (status==429 and data=={'error':'limited'}) or (status==503 and data=={'error':'busy'}): raise TemporaryUnavailable('resume temporarily unavailable')
        if status==503 and data=={'error':'storage_unavailable'}: raise RemoteOperationError('resume storage unavailable')
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('resume data corrupt')
        if status>=500: raise RemoteOperationError('resume status unavailable')
        if status!=200 or set(data)!={'manifest','state','chunks','next'} or not isinstance(data['manifest'],dict) or data['state'] not in ('receiving','publishing','complete','failed','expired','cancelled') or not isinstance(data['chunks'],list) or len(data['chunks'])>16 or (data['next'] is not None and (type(data['next']) is not int or data['next']<=cursor)): raise ProtocolError('invalid resume status')
        return data
    def resume_finish(self,transfer_id):
        sock=self.conn.sock
        if sock is None: raise NetworkError('connection closed')
        previous=sock.timeout; sock.timeout=60
        try:
            try: status,data=self.call('POST','/v1/resume/finish',{'id':transfer_id})
            except ProtocolError as e: raise UnknownOutcome('query resume state before retry') from e
        finally: sock.timeout=previous
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('resume denied')
        if (status==429 and data=={'error':'limited'}) or (status==503 and data=={'error':'busy'}): raise TemporaryUnavailable('resume temporarily unavailable')
        if status==503 and data=={'error':'storage_unavailable'}: raise RemoteOperationError('resume storage unavailable')
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('resume data corrupt')
        if status!=200 or data!={'status':'received'}: raise UnknownOutcome('query resume state before retry')
        return data
    def resume_download_meta(self,transfer_id):
        sock=self.conn.sock
        if sock is None: raise NetworkError('connection closed')
        previous=sock.timeout; sock.timeout=60
        try: status,data=self.call('GET','/v1/resume/download-meta?id='+transfer_id)
        finally: sock.timeout=previous
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('download denied')
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('download cache corrupt')
        if (status==429 and data=={'error':'limited'}) or (status==503 and data=={'error':'busy'}): raise TemporaryUnavailable('download temporarily unavailable')
        if status>=500: raise RemoteOperationError('download unavailable')
        if status!=200 or set(data)!={'version','transfer_id','package_id','size','chunks','cipher_sha256','source_sha256','key_check','context_sha256'}: raise ProtocolError('invalid download manifest')
        return data
    def resume_download_index(self,transfer_id,cursor=0):
        status,data=self.call('GET','/v1/resume/download-index?id='+transfer_id+'&cursor='+str(cursor))
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('download denied')
        if (status==429 and data=={'error':'limited'}) or (status==503 and data=={'error':'busy'}): raise TemporaryUnavailable('download index temporarily unavailable')
        if status>=500: raise RemoteOperationError('download index unavailable')
        if status!=200 or set(data)!={'chunks','next'} or not isinstance(data['chunks'],list) or len(data['chunks'])>16 or (data['next'] is not None and (type(data['next']) is not int or data['next']<=cursor)): raise ProtocolError('invalid download index')
        return data
    def resume_download_chunk(self,transfer_id,index):
        import hashlib
        from tls_transport import TLSFailure
        if type(index) is not int or index<0 or not self.token: raise ValueError('invalid download chunk')
        try:
            self.conn.request('GET','/v1/resume/download-chunk?id='+transfer_id+'&index='+str(index),headers={'Authorization':'Bearer '+self.token})
            response=self.conn.getresponse(); sizes=response.headers.get_all('Content-Length',[]); types=response.headers.get_all('Content-Type',[])
            if len(sizes)!=1 or len(types)!=1 or response.headers.get_all('Transfer-Encoding',[]) or not sizes[0].isascii() or not sizes[0].isdigit() or len(sizes[0])>6: raise ProtocolError('invalid chunk headers')
            size=int(sizes[0])
            if response.status!=200:
                if size>MAX_BODY or types[0].split(';',1)[0].strip().lower()!='application/json': raise ProtocolError('invalid chunk error')
                raw=response.read(size+1)
                if len(raw)!=size: raise ProtocolError('invalid chunk error length')
                try: error=json.loads(raw,object_pairs_hook=unique_object)
                except (ValueError,UnicodeError) as e: raise ProtocolError('invalid chunk error') from e
                if response.status==403 and error=={'error':'denied'}: raise AuthorizationError('download denied')
                if response.status==409 and error=={'error':'conflict'}: raise ProtocolError('download cache corrupt')
                if (response.status==429 and error=={'error':'limited'}) or (response.status==503 and error=={'error':'busy'}): raise TemporaryUnavailable('download temporarily unavailable')
                if response.status>=500: raise RemoteOperationError('download unavailable')
                raise ProtocolError('unexpected chunk error')
            hashes=response.headers.get_all('X-Chunk-SHA256',[])
            if not 1<=size<=256*1024 or types[0].split(';',1)[0].strip().lower()!='application/octet-stream' or len(hashes)!=1 or not re.fullmatch('[0-9a-f]{64}',hashes[0]): raise ProtocolError('invalid chunk metadata')
            data=response.read(size+1)
            if len(data)!=size or hashlib.sha256(data).hexdigest()!=hashes[0]: raise ProtocolError('download chunk integrity failed')
            return data,hashes[0]
        except (ssl.SSLError,TLSFailure,http.client.HTTPException,OSError) as e: raise NetworkError('download chunk transport failed') from e
    def transfer_cancel(self,transfer_id):
        try: status,data=self.call('POST','/v1/transfer/cancel',{'id':transfer_id})
        except ProtocolError as e: raise UnknownOutcome('cancellation outcome unknown') from e
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('cancellation denied')
        if status!=200 or data!={'status':'cancelled'}: raise UnknownOutcome('cancellation outcome unknown')
        return True
    def transfer_upload_small(self,transfer_id,ciphertext):
        import base64
        if not isinstance(ciphertext,bytes) or not 1<=len(ciphertext)<=2048: raise ValueError('one-shot upload must be at most 2048 bytes')
        try: status,data=self.call('POST','/v1/transfer/upload',{'id':transfer_id,'data':base64.b64encode(ciphertext).decode()})
        except ProtocolError as e: raise UnknownOutcome('upload outcome unknown; do not blindly retry') from e
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('upload denied')
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('transfer already published')
        if status!=200 or set(data)!={'status','files_and_directories','bytes'} or data['status']!='received' or type(data['files_and_directories']) is not int or type(data['bytes']) is not int or data['files_and_directories']<0 or data['bytes']<0: raise UnknownOutcome('upload outcome unknown; do not blindly retry')
        return data
    def transfer_upload_stream(self,transfer_id,source,length):
        from tls_transport import TLSFailure
        if not isinstance(transfer_id,str) or str(uuid.UUID(transfer_id))!=transfer_id or type(length) is not int or not 1<=length<=160*1024*1024: raise ValueError('invalid stream upload')
        if not self.token: raise AuthorizationError('authentication required')
        headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/octet-stream','Content-Length':str(length),'X-Transfer-ID':transfer_id}
        bounded=_BoundedSource(source,length,time.monotonic()+65)
        try:
            self.conn.request('POST','/v1/transfer/upload-stream',body=bounded,headers=headers)
            if bounded.remaining: raise OSError('short source')
            response=self.conn.getresponse(); lengths=response.headers.get_all('Content-Length',[]); types=response.headers.get_all('Content-Type',[])
            if len(lengths)!=1 or len(types)!=1 or response.headers.get_all('Transfer-Encoding',[]) or not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0])>5 or int(lengths[0])>MAX_BODY or types[0].split(';',1)[0].strip().lower()!='application/json': raise ProtocolError('invalid response headers')
            raw=response.read(int(lengths[0])+1)
            if len(raw)!=int(lengths[0]): raise ProtocolError('invalid response length')
            try: data=json.loads(raw,object_pairs_hook=unique_object)
            except (ValueError,UnicodeDecodeError) as e: raise ProtocolError('invalid JSON') from e
            status=response.status
        except (ssl.SSLError,TLSFailure,OSError,http.client.HTTPException,ProtocolError,ValueError) as e: raise UnknownOutcome('retain transfer ID and query upload outcome') from e
        finally: self.close()
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('upload denied')
        if status==409 and data=={'error':'conflict'}: raise ProtocolError('transfer already published')
        if status!=200 or not isinstance(data,dict) or set(data)!={'status','files_and_directories','bytes'} or data['status']!='received' or type(data['files_and_directories']) is not int or type(data['bytes']) is not int or data['files_and_directories']<0 or data['bytes']<0: raise UnknownOutcome('retain transfer ID and query upload outcome')
        return data
    def transfer_download_stream(self,transfer_id,package_id,staging):
        """Write ciphertext only to caller-owned private staging; never publish partial output."""
        from tls_transport import TLSFailure
        if not self.token: raise AuthorizationError('authentication required')
        if str(uuid.UUID(transfer_id))!=transfer_id or str(uuid.UUID(package_id))!=package_id: raise ValueError('invalid download id')
        deadline=time.monotonic()+65
        try:
            self.conn.sock.timeout=60
            self.conn.request('GET','/v1/transfer/download?id='+transfer_id,headers={'Authorization':'Bearer '+self.token})
            response=self.conn.getresponse(); lengths=response.headers.get_all('Content-Length',[]); types=response.headers.get_all('Content-Type',[])
            if len(lengths)!=1 or len(types)!=1 or response.headers.get_all('Transfer-Encoding',[]) or not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0])>9: raise ProtocolError('invalid response headers')
            size=int(lengths[0])
            if response.status!=200:
                if size>MAX_BODY or types[0].split(';',1)[0].strip().lower()!='application/json': raise ProtocolError('invalid error response')
                raw=response.read(size+1)
                if len(raw)!=size: raise ProtocolError('invalid error length')
                try: error=json.loads(raw,object_pairs_hook=unique_object)
                except (ValueError,UnicodeError) as e: raise ProtocolError('invalid error response') from e
                if response.status==403 and error=={'error':'denied'}: raise AuthorizationError('download denied')
                if response.status==429 or response.status>=500: raise RemoteOperationError('download unavailable')
                raise ProtocolError('unexpected download response')
            packages=response.headers.get_all('X-Package-ID',[])
            if types[0].split(';',1)[0].strip().lower()!='application/octet-stream' or packages!=[package_id] or not 1<=size<=160*1024*1024: raise ProtocolError('invalid download metadata')
            remaining=size; self.conn.sock.timeout=5
            while remaining:
                if time.monotonic()>=deadline: raise NetworkError('download deadline exceeded')
                block=response.read(min(65536,remaining))
                if not block: raise ProtocolError('incomplete download')
                view=memoryview(block)
                while view:
                    try: written=staging.write(view)
                    except OSError as e: raise LocalStorageError('staging write failed') from e
                    if not isinstance(written,int) or written<=0 or written>len(view): raise LocalStorageError('incomplete staging write')
                    view=view[written:]
                remaining-=len(block)
            return size
        except (ssl.SSLError,TLSFailure,http.client.HTTPException,OSError) as e: raise NetworkError('download transport failed') from e
        finally: self.close()
    def transfer_upload_result(self,transfer_id):
        status,data=self.call('GET','/v1/transfer/upload-result?id='+transfer_id)
        if status==404 and data=={'error':'not_found'}: return None
        if status==403 and data=={'error':'denied'}: raise AuthorizationError('upload query denied')
        if status>=500: raise RemoteOperationError('upload query unavailable')
        if status!=200 or data!={'id':transfer_id,'status':'received'}: raise ProtocolError('invalid upload query')
        return data
    def enroll(self,otp,xkey):
        import base64,hashlib
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        from enrollment import raw_public, transcript, proof
        edpub=raw_public(self.key.public_key()); xpub=raw_public(xkey.public_key())
        status,value=self.call('POST','/v1/enroll/challenge',{'owner':self.owner,'device':self.device,'edpub':base64.b64encode(edpub).decode(),'xpub':base64.b64encode(xpub).decode()})
        if status!=200 or set(value)!={'nonce','epub'}: raise AuthorizationError('enrollment unavailable')
        try: nonce=base64.b64decode(value['nonce'],validate=True); epub=base64.b64decode(value['epub'],validate=True)
        except (ValueError,TypeError) as e: raise ProtocolError('invalid enrollment challenge') from e
        if len(nonce)!=32 or len(epub)!=32: raise ProtocolError('invalid enrollment challenge')
        channel=hashlib.sha256(self.conn.sock.exporter()).digest(); server=hashlib.sha256(self.conn.sock.getpeercert(binary_form=True)).digest()
        message=transcript(server,channel,nonce,self.owner,self.device,edpub,xpub,epub,otp)
        try: mac=proof(xkey.exchange(X25519PublicKey.from_public_bytes(epub)),nonce,message)
        except ValueError as e: raise ProtocolError('invalid enrollment key') from e
        payload={'otp':otp,'signature':base64.b64encode(self.key.sign(message)).decode(),'proof':base64.b64encode(mac).decode()}
        try: status,result=self.call('POST','/v1/enroll/complete',payload)
        except ProtocolError as e: raise UnknownOutcome('enrollment outcome unknown; authenticate using retained keys') from e
        if status==403 and result=={'error':'denied'}: raise AuthorizationError('enrollment denied')
        if status==409 and result=={'error':'conflict'}: raise ProtocolError('device conflict')
        if status!=200 or result!={'status':'enrolled'}: raise UnknownOutcome('enrollment outcome unknown; authenticate using retained keys')
        return True
