"""Bounded TCP forwarder for disposable private-network tests only."""
import select, socket, sys, threading
listen,port,target,targetport=sys.argv[1],int(sys.argv[2]),sys.argv[3],int(sys.argv[4])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((listen,port)); s.listen(8); s.settimeout(30)
slots=threading.BoundedSemaphore(8)
def relay(src):
 dst=None
 try:
  dst=socket.create_connection((target,targetport),timeout=4); src.settimeout(4)
  while True:
   ready,_,_=select.select([src,dst],[],[],8)
   if not ready: break
   for item in ready:
    data=item.recv(65536)
    if not data: return
    (dst if item is src else src).sendall(data)
 except OSError: pass
 finally:
  src.close()
  if dst: dst.close()
  slots.release()
print('READY',flush=True)
while True:
 try: c,_=s.accept()
 except socket.timeout: break
 if not slots.acquire(False): c.close(); continue
 threading.Thread(target=relay,args=(c,),daemon=True).start()
