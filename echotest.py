import sys
try:
    sys.path.append("/home/fady/Documents/PlayGround/secondtest/src/")
except: print("\033[91mCouldn't find Playground where Fady put it. So you're probably not Fady.\033[0m")

'''
Created on Feb 15, 2014

@author: sethjn

This sample shows how to do some basic things with playground.
It does not use the PlaygroundNode interface. To see an example
of that, check out computePi.py.
'''
# Import playgroundlog to enable logging
from playground import playgroundlog

# We will use "BOOL1" and "STRING" in our message definition
from playground.network.message.StandardMessageSpecifiers import BOOL1, STRING

from playground.network.common import PlaygroundAddress

# MessageDefinition is the base class of all automatically serializable messages
from playground.network.message.ProtoBuilder import MessageDefinition

from playground.twisted.endpoints import GateServerEndpoint, GateClientEndpoint
from playground.twisted.error.ErrorHandlers import TwistedShutdownErrorHandler

from twisted.internet import defer, stdio
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory, connectionDone
from twisted.protocols import basic

import sys, time, os, logging
from twisted.internet.endpoints import connectProtocol
from playground.network.common.Timer import callLater
logger = logging.getLogger(__name__)

class EchoProtocolMessage(MessageDefinition):
    """
    EchoProtocolMessage is a simple message for sending a bit of 
    data and getting the same data back as a response (echo). The
    "header" is simply a 1-byte boolean that indicates whether or
    not it is the original message or the echo.
    """
    
    # We can use **ANY** string for the identifier. The convention is to
    # Do a fully qualified name of some set of messages. I have been
    # putting my messages under playground.fall2013.base. You can 
    # put your in a package, or have them flat like shown below
    PLAYGROUND_IDENTIFIER = "TestEchoProtocolMessageID"
    
    # Message version needs to be x.y where x is the "major" version
    # and y is the "minor" version. All Major versions should be
    # backwards compatible. Look at "ClientToClientMessage" for
    # an example of multiple versions
    MESSAGE_VERSION = "1.0"
    BODY = [
            ("original", BOOL1),
            ("data", STRING)
            ]


class EchoServerProtocol(Protocol):
    """
    This is our class for the Server's protocol. It simply receives
    an EchoProtocolMessage and sends back a response
    """
    def __init__(self):
        self.buffer = ""
        
    def connectionLost(self, reason=connectionDone):
        print "Lost connection to client. Cleaning up."
        Protocol.connectionLost(self, reason=reason)
        
    def dataReceived(self, data):
        self.buffer += data
        try:
            echoMessage, bytesUsed = EchoProtocolMessage.Deserialize(data)
            self.buffer = self.buffer[bytesUsed:]
        except Exception, e:
            print "We had a deserialization error", e
            return

        echoMessage.original = False
        print "Received echo message", echoMessage.data        
        
        # Use the transport to write the data back. Now, just so you know, self.transport
        # is of type  ClientApplicationTransport. Internally, it is wrapping your message
        # into a Client-to-Client message.
        self.transport.write(echoMessage.__serialize__())
        if echoMessage.data == "__QUIT__":
            self.callLater(0, self.transport.loseConnection)
        self.buffer and self.dataReceived('')
        
        
class EchoClientProtocol(Protocol):
    """
    This is our class for the Client's protocol. It provides an interface
    for sending a message. When it receives a response, it prints it out.
    """
    def __init__(self, callback):
        self.buffer = ""
        self.callback = callback
        
    def close(self):
        self.__sendMessageActual("__QUIT__")
        
    def connectionMade(self):
        print "Echo client connection made"
        
    def dataReceived(self, data):
        self.buffer += data
        try:
            echoMessage, bytesUsed = EchoProtocolMessage.Deserialize(data)
            self.buffer = self.buffer[bytesUsed:]
        except Exception, e:
            print "We had a deserialization error", e
            return

        echoMessage.original = False
        self.callback(echoMessage.data)       
        
        self.buffer and self.dataReceived('')
        
    def send(self, data):
        # Get the builder for the EchoProtocolMessage
        echoMessage = EchoProtocolMessage(original=True)
        echoMessage.data = data
        
        # In this example, instead of calling transport.writeMessage, we serialize ourselves
        self.transport.write(echoMessage.__serialize__())
        
class EchoServer(Factory):
    protocol=EchoServerProtocol
    
class EchoClientFactory(Factory):
    protocol=EchoClientProtocol
    
class ClientTest(basic.LineReceiver):
    """
    This class is used to test sending a bunch of messages over
    the echo protocol.
    """
    delimiter = os.linesep
    
    def __init__(self, echoServerAddr, endpoint):
        self.__echoServerAddr = echoServerAddr
        self.__protocol = None
        self.__endpoint = endpoint
        self.__d = None
        
    def __handleError(self, e):
        print "had a failure", e
        raise Exception("Failure: " + str(e))
    
    def __handleEcho(self, msg):
        print "\nReceived message from server: %s" % msg
        self.reset()
    
    def connectionLost(self, reason=connectionDone):
        callLater(1.0, reactor.stop)
        
    def connectionMade(self):
        #self.__echoServerAddr = PlaygroundAddress.FromString(self.__echoServerAddr)
        self.__protocol = EchoClientProtocol(self.__handleEcho)
        self.__d = connectProtocol(self.__endpoint, self.__protocol)
        self.__d.addCallback(self.echoConnectionMade)
        self.__d.addErrback(self.__handleError)
            
    def echoConnectionMade(self, status):
        self.transport.write("Message to send to %s (quit to exit): " % self.__echoServerAddr)
        
    def lineReceived(self, line):
        if not self.__protocol:
            self.transport.write("Protocol not yet ready.\n")
        message = line
        if message.lower().strip() in ["quit", "__quit__"]:
            self.__protocol.transport.loseConnection()
            self.__protocol = None
            self.exit("Normal Exit")
            return
        else:
            self.__protocol.send(message)
            self.reset()
            
    def reset(self):
        self.transport.write("\nMessage to send to %s (quit to exit): " % self.__echoServerAddr)
        
    def exit(self, reason=None):
        print "Shutdown of echo test client. Reason =", reason
        if self.transport:
            self.transport.loseConnection()
        

USAGE = """usage: echotest <mode> [--gate=<gatekey> --stack=<stack>]
  mode is either 'server' or a server's address (client mode)"""

if __name__=="__main__":
    echoArgs = {}
    
    args= sys.argv[1:]
    i = 0
    for arg in args:
        if arg.startswith("-"):
            k,v = arg.split("=")
            echoArgs[k]=v
        else:
            echoArgs[i] = arg
            i+=1
    
    if not echoArgs.has_key(0):
        sys.exit(USAGE)
    gateKey = echoArgs.get("--gate",None)
    stack = echoArgs.get("--stack",None)
    portNum = int(echoArgs.get("--port","101"))
    if stack:
        exec("import " + stack)
        networkStack = eval(stack)
    mode = echoArgs[0]
    
    # Turn on logging
    logctx = playgroundlog.LoggingContext("echo_"+str(mode))
    
    # Uncomment the next line to turn on "packet tracing"
    #logctx.doPacketTracing = True
    
    playgroundlog.startLogging(logctx)
    playgroundlog.UseStdErrHandler(True)
    
    # Set up the client base
    #client = ClientBase(myAddress)
    #serverAddress, serverPortString = sys.argv[1:3]
    #chaperonePort = 9090#int(serverPortString)
    
    if mode.lower() == "server":
        # This guy will be the server. Create an instance of the factory
        echoProtocolServer = EchoServer()
        
        # install the echoProtocolServer (factory) on playground port 101
        #client.listen(echoProtocolServer, 101, connectionType=connectionType)
        
        # tell the playground client to connect to playground server and start running
        #client.connectToChaperone(chaperoneAddr, chaperonePort)
        echoServerEndpoint = GateServerEndpoint.CreateFromConfig(reactor, portNum, gateKey, networkStack=networkStack)
        d = echoServerEndpoint.listen(echoProtocolServer)
        d.addErrback(logger.error)
        
        
    else:
        echoServerAddr = mode
        #try:
        #    echoServerAddr = PlaygroundAddress.FromString(mode)
        #except:
        #    sys.exit(USAGE)
        # This guy will be the client. The server's address is hard coded
        echoClientEndpoint = GateClientEndpoint.CreateFromConfig(reactor, echoServerAddr, portNum, gateKey, networkStack=networkStack)
        tester = ClientTest(echoServerAddr, echoClientEndpoint)
        
        stdio.StandardIO(tester)

    TwistedShutdownErrorHandler.HandleRootFatalErrors()    
    reactor.run()
