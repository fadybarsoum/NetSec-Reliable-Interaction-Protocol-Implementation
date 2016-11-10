from playground.network.common.Protocol import MessageStorage
from playground.network.common.Protocol import StackingTransport, StackingProtocolMixin, StackingFactoryMixin
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import UINT4, UINT1, OPTIONAL, STRING, DEFAULT_VALUE, LIST, BOOL1

from twisted.internet.protocol import Protocol, Factory

from Crypto.Cipher import AES
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
        print("   Key #\t%s" % msg.key)
        print("    IV #\t%s" % msg.IV)
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
    
    def tSend(s, ripMessage):
        s.lowerTransport().write(kissMessage.__serialize__())

class KissProtocol(StackingProtocolMixin, Protocol):
    def __init__(s):
    	s.debug = True
    	s.errordebug = True
    	s.statusdebug = False

    	s.addr = "new"
    	s.messages = MessageStorage()
    	s.connected = False

	def makeConnection(s, transport):
		StackingProtocolMixin.__init__(s)
        s.transport = KissTransport(transport, s)
        s.addr = transport.getHost().host

    	zKey = urandom(32)
    	IV = urandom(16)
    	IV_i = int(IV.encode('hex'), 16)
    	IV_c1 = Counter.new(128, initial_value=IV_asInt)
    	IV_c2 = Counter.new(128, initial_value=IV_asInt)
    	s.aesEnc = AES.new(zKey,counter=IV_c1, mode=AES.MODE_CTR)
    	s.aesDec = AES.new(zKey,counter=IV_c2, mode=AES.MODE_CTR)

    	s.lowerProtocol().getPeer()

	def connectionMade(s):

	def dataReceived(s,data):

	def loseConnection(s):
        s.kissPrintError("Lose Connection called")
        s.higherProtocol().connectionLost()
        s.transport.loseConnection()
        s.transport.lowerTransport().loseConnection()

    def connectionLost(s, reason):
        # called when connection is lost, should keep processing
        super(RIPProtocol, s).connectionLost()    

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
        super(RIPServerProtocol, s).__init__()

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