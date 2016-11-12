import sys
try:
    sys.path.append("~/Documents/PlayGround/secondtest/src/")
except: print("\033[91mCouldn't find Playground where Fady put it. So you're probably not Fady.\033[0m")

from playground.network.common.Protocol import MessageStorage
from playground.network.common.Protocol import StackingTransport, StackingProtocolMixin, StackingFactoryMixin
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import UINT4, UINT1, OPTIONAL, STRING, DEFAULT_VALUE, LIST, BOOL1

from twisted.internet.protocol import Protocol, Factory

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from os import urandom

class KissHandShake(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissHandShake"
    MESSAGE_VERSION = "1.0"

    BODY = [("key", STRING), # strictly 32 bytes
            ("IV", STRING) # strictly 16 bytes
        ]

    def printMessageNicely(msg):
        print("\033[94m[KISS HANDSHAKE MESSAGE]")
        print("   Key #\t%s" % int(msg.key.encode('hex'), 16))
        print("    IV #\t%s" % int(msg.IV.encode('hex'), 16))
        print("[END KISS HANDSHAKE MESSAGE]\033[0m")

class KissData(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "KissData"
    MESSAGE_VERSION = "1.0"

    BODY = [("data", STRING)
        ]

    def printMessageNicely(msg):
        print("\033[94m[KISS MESSAGE]")
        print("\t%s" % msg.data)
        print("[END KISS MESSAGE]\033[0m")

class KissTransport(StackingTransport):
    def __init__(s, lowerTransport, kissproto):
        StackingTransport.__init__(s, lowerTransport)
        s.kissP = kissproto
        
    def write(s, data):
        kissMessage = s.kissP.processOut(data)
    
    def tSend(s, kissMessage):
        s.lowerTransport().write(kissMessage.__serialize__())

class KissProtocol(StackingProtocolMixin, Protocol):
    def __init__(s):
        s.debug = False
        s.errordebug = False
        s.statusdebug = False

        s.addr = "new"
        s.messages = MessageStorage()

        s.connected = False

    def makeConnection(s, transport):
        StackingProtocolMixin.__init__(s)
        s.transport = KissTransport(transport, s)
        s.addr = transport.getHost().host

        myKey = urandom(32)
        myIV = urandom(16)
        myIV_i = int(myIV.encode('hex'), 16)
        myIV_c = Counter.new(128, initial_value=myIV_i)
        s.enc = AES.new(myKey,counter=myIV_c, mode=AES.MODE_CTR)

        s.peer = s.transport.getPeer()
        msg = KissHandShake()
        peerPubK = RSA.importKey(s.peer.certificateChain[0].getPublicKeyBlob())
        RSAenc = PKCS1_OAEP.new(peerPubK)
        msg.IV = RSAenc.encrypt(myIV)
        msg.key = RSAenc.encrypt(myKey)

        s.kissPrint("Sending handshake")
        s.transport.tSend(msg)

    def connectionMade(s):
        s.connected = True
        s.makeHigherConnection(s.transport)
        s.kissPrint("Higher connection made")

    def dataReceived(s,data):
        #try:
        s.messages.update(data)
        #except: s.kissPrintError("MessageStorage update failure")
        #try:
        for msg in s.messages.iterateMessages():
            if s.connected == False:
                s.processHandshake(msg)
            else:
                s.processDataIn(msg)
#except: s.kissPrintError("Error redirecting incoming message")
        
    def processHandshake(s,msg):
        s.kissPrint("Processing incoming handshake")
        lowerHost = s.transport.getHost()
        myPrivK = lowerHost.privateKey
        RSAdec = PKCS1_OAEP.new(myPrivK)
        peerIV = RSAdec.decrypt(msg.IV)
        peerKey = RSAdec.decrypt(msg.key)
        peerIV_i = int(peerIV.encode('hex'), 16)
        peerIV_c = Counter.new(128, initial_value=peerIV_i)
        s.dec = AES.new(peerKey,counter=peerIV_c, mode=AES.MODE_CTR)
        s.kissPrint("peer AES decrypter instantiated")

        s.connectionMade()

    def processDataIn(s,msg):
        plaintext = s.dec.decrypt(msg.data)
        s.higherProtocol() and s.higherProtocol().dataReceived(plaintext)

    def processOut(s,data):
        cyphertext = s.enc.encrypt(data)
        msg = KissData()
        msg.data = cyphertext
        s.transport.tSend(msg)

    def loseConnection(s):
        s.kissPrintError("Lose Connection called")
        s.transport.loseConnection()
        s.transport.lowerTransport().loseConnection()
        s.higherProtocol().loseConnection()
        s.ripPrintError("Shut down complete!")

    def connectionLost(s):
        s.kissPrintError("Connection Lost called")
        # called when connection is lost, should keep processing
        s.higherProtocol().connectionLost()
        super(KissProtocol, s).connectionLost()    

    def close(s):
        s.kissPrintError("Recevied Close command")
        s.loseConnection()

    def kissPrint(s, thestr):
        if s.debug:
            print("\033[95;1m[KISS %s]\033[92m %s\033[0m" % (s.addr,thestr))

    def kissPrintError(s, thestr):
        if s.errordebug:
            print("\033[95;1m[KISS %s]\033[91m %s\033[0m" % (s.addr,thestr))

    def printStatus(s):
        print("\033[95;1m[KISS %s]\033[93m cnctd=%s \033[0m" % (s.addr, s.connected))
        s.deferreds.append( deferLater(reactor, 1, s.printStatus))

class KissServerProtocol(KissProtocol):
    def __init__(s):
        super(KissServerProtocol, s).__init__()

    def kissPrint(s, thestr):
        if s.debug:
            print("\033[94;40;1m[KISS %s]\033[92m %s\033[0m" % (s.addr,thestr))

    def kissPrintError(s, thestr):
        if s.errordebug:
            print("\033[94;40;1m[KISS %s]\033[91m %s\033[0m" % (s.addr,thestr))

    def printStatus(s):
        print("\033[94;40;1m[KISS %s]\033[93m cnctd=%s \033[0m" % (s.addr,s.connected))
        s.deferreds.append( deferLater(reactor, 1, s.printStatus))

class KissFactory(StackingFactoryMixin, Factory):
    protocol = KissProtocol

class KissServerFactory(KissFactory):
    protocol = KissServerProtocol
    
ConnectFactory = KissFactory
ListenFactory = KissServerFactory