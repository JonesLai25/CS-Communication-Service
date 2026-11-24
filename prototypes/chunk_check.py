"""Disposable chunk/reconciliation experiment; not a wire format or production key storage."""
if not __debug__: raise RuntimeError('security checks require Python without -O')
import hashlib, json, os, pathlib, signal, subprocess, sys, tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
CHUNK=1024
class Corrupt(Exception): pass

def digest(b): return hashlib.sha256(b).hexdigest()
def durable(path,data):
    temp=path.with_suffix(path.suffix+'.partial')
    with open(temp,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(temp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def prepare(p,data,key,tid):
    p=pathlib.Path(p); (p/'out').mkdir(); (p/'in').mkdir()
    durable(p/'source',data); a=AESGCM(key); hashes=[]; total=(len(data)+CHUNK-1)//CHUNK
    for i in range(total):
        aad=tid.encode()+i.to_bytes(8,'big')+total.to_bytes(8,'big')
        ct=a.encrypt(i.to_bytes(12,'big'),data[i*CHUNK:(i+1)*CHUNK],aad)
        durable(p/'out'/str(i),ct); hashes.append(digest(ct))
    m={'transfer':tid,'source':digest(data),'key':digest(key),'count':total,'hashes':hashes}
    durable(p/'manifest',json.dumps(m,sort_keys=True).encode()); return m

def resume(p,key,tid):
    p=pathlib.Path(p); m=json.loads((p/'manifest').read_text()); data=(p/'source').read_bytes()
    if m['transfer']!=tid or m['key']!=digest(key) or m['source']!=digest(data) or m['count']!=(len(data)+CHUNK-1)//CHUNK or len(m['hashes'])!=m['count']: raise Corrupt('manifest mismatch')
    # Ciphertexts are generated once; never encrypt during resume.
    a=AESGCM(key); out=[]
    for i in range(m['count']):
        src=p/'out'/str(i); dst=p/'in'/str(i)
        if not src.exists() or digest(src.read_bytes())!=m['hashes'][i]: raise Corrupt('source chunk missing or damaged')
        ct=src.read_bytes(); aad=tid.encode()+i.to_bytes(8,'big')+m['count'].to_bytes(8,'big')
        try: plain=a.decrypt(i.to_bytes(12,'big'),ct,aad)
        except InvalidTag as e: raise Corrupt('AEAD') from e
        # Progress is derived from verified bytes, not trusted as sole truth.
        if not dst.exists() or digest(dst.read_bytes())!=m['hashes'][i]: durable(dst,ct)
        out.append(plain)
    result=b''.join(out)
    if digest(result)!=m['source']: raise Corrupt('archive mismatch')
    durable(p/'progress',json.dumps({'verified':m['count']}).encode())
    return result

def rejected(fn):
    try: fn()
    except Corrupt: return
    raise AssertionError('invalid transfer accepted')

def main():
 with tempfile.TemporaryDirectory() as d:
    p=pathlib.Path(d); key=os.urandom(32); data=os.urandom(5000); tid='test-transfer'; m=prepare(p,data,key,tid)
    proc=subprocess.Popen([sys.executable,__file__,'wait',str(p)],stdout=subprocess.PIPE,text=True)
    try:
        import select
        if not select.select([proc.stdout],[],[],5)[0]: raise TimeoutError('child startup')
        assert proc.stdout.readline().strip()=='ready'
        proc.send_signal(signal.SIGKILL); proc.wait(timeout=5)
    finally:
        if proc.poll() is None: proc.kill(); proc.wait(timeout=5)
        proc.stdout.close()
    # The killed worker left a partial chunk and inconsistent progress.
    assert (p/'in'/'0.partial').exists()
    assert resume(p,key,tid)==data and digest((p/'in'/'0').read_bytes())==m['hashes'][0]
    rejected(lambda: resume(p,key,'wrong')); rejected(lambda: resume(p,os.urandom(32),tid))
    (p/'source').write_bytes(data+b'changed'); rejected(lambda: resume(p,key,tid)); (p/'source').write_bytes(data)
    c0=(p/'out'/'0').read_bytes(); c1=(p/'out'/'1').read_bytes()
    (p/'out'/'0').write_bytes(c0[:-1]+bytes([c0[-1]^1])); rejected(lambda: resume(p,key,tid))
    (p/'out'/'0').write_bytes(c1); (p/'out'/'1').write_bytes(c0); rejected(lambda: resume(p,key,tid))
    (p/'out'/'0').unlink(); rejected(lambda: resume(p,key,tid))
    print('manifest/source/key/ID, missing/reordered/tampered chunks, SIGKILL and reconciliation negative controls: PASS')
if __name__=='__main__':
 if len(sys.argv)>1:
    p=pathlib.Path(sys.argv[2]); (p/'in'/'0.partial').write_bytes(b'partial'); (p/'in'/'0').write_bytes(b'damaged'); (p/'progress').write_text('{"verified":5}'); print('ready',flush=True); signal.pause()
 else: main()
