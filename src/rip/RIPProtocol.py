'''
Implementation of The Reliable Interaction Protocol (RIP)
Transport Layer on the Playground network

As drafted by JHU's Fall 2016 Network Security class's PETF
Implemented using Twisted 16.4.1

Author: Fady Barsoum
Created: 02OCT2016 1:05AM
'''

import sys
try:
    sys.path.append("/home/fady/Documents/PlayGround/secondtest/src/")
except: print("\033[94mCouldn't find Playground where Fady put it. So you're probably not Fady.\033[0m")

import playground
from playground.crypto import X509Certificate
from playground.network.common.statemachine import StateMachine
from playground.network.common.Protocol import MessageStorage
from playground.network.common.Protocol import StackingTransport, StackingProtocolMixin, StackingFactoryMixin
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import UINT4, UINT1, OPTIONAL, STRING, DEFAULT_VALUE, LIST, BOOL1

from twisted.internet import reactor
from twisted.internet.task import deferLater
from twisted.internet.protocol import Protocol, Factory

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


from os import urandom
from struct import unpack

from CertFactory import CertFactory as cf

class RIPMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RIP.RIPMessage"
    MESSAGE_VERSION = "1.2"

    BODY = [("sequence_number", UINT4),
            ("acknowledgement_number", UINT4, OPTIONAL),
            ("signature", STRING, DEFAULT_VALUE("")),
            ("certificate", LIST(STRING), OPTIONAL),
            ("sessionID", STRING),
            ("acknowledgement_flag", BOOL1, DEFAULT_VALUE(False)),
            ("close_flag", BOOL1, DEFAULT_VALUE(False)),
            ("sequence_number_notification_flag", BOOL1, DEFAULT_VALUE(False)),
            ("reset_flag",  BOOL1, DEFAULT_VALUE(False)),
            ("data", STRING,DEFAULT_VALUE("")),
            ("OPTIONS", LIST(STRING), OPTIONAL)
        ]

    def printMessageNicely(msg):
        print("\033[94m[RIP MESSAGE]")
        if msg.sequence_number_notification_flag == True:
            print(">> [SNN] <<")
        print("   Sequence #\t%s" % msg.sequence_number)
        print("Acknowledge #\t%s" % msg.acknowledgement_number)
        print(" Session ID #\t%s" % msg.sessionID)
        if "UNSET" not in str(msg.certificate):
            print("Cert list len\t%s" % len(msg.certificate))
        print("DATA (%s):" % (len(msg.data)))
        print(msg.data)
        print("[END RIP MESSAGE]\033[0m")
    
class RIPTransport(StackingTransport):
    def __init__(s, lowerTransport, ripproto):
        StackingTransport.__init__(s, lowerTransport)
        s.ripP = ripproto
        
    def write(s, data):
        ripMessage = s.ripP.processOut(data)
    
    def tSend(s, ripMessage):
        s.lowerTransport().write(ripMessage.__serialize__())

class RIPProtocol(StackingProtocolMixin, Protocol):
    def __init__(s):
        s.messages = MessageStorage()
        s.OBBuffer = "" # outbound buffer, should prbly be a list
        s.fsm = s.RIP_FSM()
        s.connected = False
        
        s.seqnum = 0 # gets set later but this should be the sequence of the next new packet
        s.lastAckRcvd = None # this is the sequence number the other party expects
        s.sentMsgs = dict() # do not retransmit ACKs!! key: sequence number
        
        s.expectedSeq = None # this is the sequence number of the next expected packet
        s.lastAckSent = None # this is what we told the other party we're expecting
        s.rcvdMsgs = dict() # unprocessed rcvdMsgs
        s.deferreds = list() # so we can disable them when shutting down
        
        s.MSS = 2048 # fixed
        s.retransmit_delay = 0.2 # we can lower this
        s.maxRetries = 60 # we need to increase this to 256
        s.sessionID = "" # gets set after nonces are exchanged
        s.myNonce = urandom(8).encode('hex') # random hex nonce
        
        s.otherCert = None # store the other certs here
        s.otherCA = None
        
    def makeConnection(s, transport):
        StackingProtocolMixin.__init__(s)
        s.ripT = RIPTransport(transport, s)
        s.transport = s.ripT

        addr = str(transport.getHost().host)[-4:]
        s.ripPrint("Host: " + addr)
        s.mykey = RSA.importKey(cf.getPrivateKeyForAddr(addr))
        s.signer = PKCS1_v1_5.new(s.mykey)
        certFiles = cf.getCertsForAddr(addr)
        rootcertfile = cf.getRootCert()
        s.rootcert = X509Certificate.loadPEM(rootcertfile)
        s.myCert = X509Certificate.loadPEM(certFiles[0])
        s.CAcert = X509Certificate.loadPEM(certFiles[1])

        s.startFSM()

    def connectionMade(s):
        s.makeHigherConnection(s.ripT)
        s.ripPrint("Higher connection made")

    # Checks then routes the incoming message to the appropriate parser
    def dataReceived(s,data):
        s.messages.update(data)
        for msg in s.messages.iterateMessages():
            s.ripPrint("Received #" + str(msg.sequence_number) + " ACK# " + str(msg.acknowledgement_number))
            if s.isDuplicate(msg):
                s.ripPrint("Got a duplicate non-ACK message")
                continue # discard this message
            if not s.checkSignature(msg):
                s.ripPrint("Signature doesn't match/certs invalid")
                continue # discard this message
            #try:
            if not s.connected: # there must be an FSM way to do this...
                if msg.acknowledgement_flag == True: # is this an ACK of a SNN
                    if msg.sequence_number_notification_flag == True: # and an SNN
                        if "UNSET" not in str(msg.certificate) and int(msg.certificate[1],16) == int(s.myNonce,16)+1: # Check nonce
                            s.lastAckRcvd = max(s.lastAckRcvd, msg.acknowledgement_number)
                            s.ripPrint("ACK received and updated")
                            s.fsm.signal("RECV_SNN_ACK", msg)
                        else: # it failed the Nonce Check
                            continue # toss it (for now)
                    elif "UNSET" not in str(msg.certificate) and int(msg.certificate[0],16) == int(s.myNonce,16)+1: # this should be just an ACK of an SNN
                        s.connected = True
                        s.lastAckRcvd = max(s.lastAckRcvd, msg.acknowledgement_number)
                        s.ripPrint("ACK received and updated")
                        s.fsm.signal("ACK_RCVD", msg)
                    else: # this ACK failed the Nonce test
                        continue # toss it (for now)
                elif msg.sequence_number_notification_flag == True: # this should be an initial SNN
                    s.fsm.signal("RECV_SNN", msg)
                else: # we're not connected and we didn't get an SNN nor ACK of SNN
                    # we might want to keep this message for later processing but the safest option is to discard it:
                    continue # discard this message
            
            else: # we're already connected
                # Check if an SNN is received (error) and (for now) kill the connection 
                if msg.sequence_number_notification_flag == True:
                    s.fsm.signal("RECV_SNN_AFTER_ESTAB", msg)
                    return

                #except: s.ripPrint("No seqflag or ack flag")
                try:
                    if msg.close_flag == True:
                        if msg.acknowledgement_flag == True:
                            s.fsm.signal("CLOSE_ACK_RCVD", msg)
                        else:
                            s.fsm.signal("RECV_CLOSE", msg)
                except: s.ripPrint("Error with closed flags happened")

                s.processDataIn(msg)
            
    def processDataIn(s, msg):
    #try:
        s.ripPrint("Processing data in")
        s.rcvdMsgs[msg.sequence_number] = msg
        updateFlag = True
        while updateFlag:
            updateFlag = False
            s.ripPrint("Looking for expectedSeq # %s in rcvdMsgs (%s)" % (s.expectedSeq,len(s.rcvdMsgs)))
            for prevk in s.rcvdMsgs.keys():
                prior = s.rcvdMsgs[prevk]
                # need to add something that will clean up < expected sequence messages
                if prior.sequence_number == s.expectedSeq:
                    s.ripPrint("Found the msg process")
                    prior = s.rcvdMsgs.pop(prevk, None)
                    updateFlag = True
                    s.expectedSeq+=len(prior.data)
                    s.sendAck(prior)
                    if len(prior.data) > 0:
                        s.higherProtocol() and s.higherProtocol().dataReceived(prior.data)
                    if prior.acknowledgement_flag == True:
                        s.lastAckRcvd = max(s.lastAckRcvd, prior.acknowledgement_number)
                        s.ripPrint("ACK received and processed (%s)" % s.lastAckRcvd)
                    
    #except: s.ripPrint("Error with transferring data up")
    
    def sendMessage(s, msg, triesLeft):
        # checks to see if the message should be sent
        s.ripPrint("Want to send # %s  Last ACK Rcvd: %s" % (msg.sequence_number, s.lastAckRcvd))
        msg.printMessageNicely()
        if msg.sequence_number < s.lastAckRcvd:
            if not (msg.acknowledgement_flag == True and ("UNSET" in str(msg.sequence_number_notification_flag) or msg.sequence_number_notification_flag == False)):
                s.sentMsgs.pop(msg.sequence_number, None)
                return

        if triesLeft <= 0:
            s.sentMsgs.pop(msg.sequence_number, None)
            '''
            if "UNSET" not in str(msg.acknowledgement_flag):
                s.killConnection("NO-RESPONSE", msg)
            '''
            return
            
        msg = s.signMessage(msg)
        # send message
        s.ripPrint("Sending # %s  ACK# %s  triesLeft= %d" % (msg.sequence_number, msg.acknowledgement_number, triesLeft))
        s.ripT.tSend(msg)
        # callback for retransmit unless it's a non-SNN, non-Close ACK
        if msg.sequence_number_notification_flag or msg.close_flag or not msg.acknowledgement_flag:
            s.deferreds.append( deferLater(reactor, s.retransmit_delay, s.sendMessage, msg, triesLeft-1) )
    
    def processOut(s, data):
        s.OBBuffer += data
        bufferSize = len(s.OBBuffer)
        while bufferSize > 0:
            bufferSize = len(s.OBBuffer)
            EoB = min(bufferSize, s.MSS)
            dataseg = s.OBBuffer[:EoB]
            s.OBBuffer = s.OBBuffer[EoB:]
            msg = RIPMessage()
            msg.data = dataseg
            msg.sequence_number = s.seqnum
            s.seqnum += len(dataseg)+1
            msg.sessionID = s.sessionID
            s.sentMsgs[msg.sequence_number] = msg
            s.sendMessage(msg, s.maxRetries)
    
    def isDuplicate(s, msg):
        # should check if the message has already been seen
        if msg.acknowledgement_flag == True:
            s.ripPrint("isDuplicate: Letting ACK through")
            return False
        if msg.sequence_number < s.lastAckSent:
            s.ripPrint("Received #%s but last Ack sent #%s" % (msg.sequence_number, s.lastAckSent))
            return True
        if msg.sequence_number in s.rcvdMsgs.keys():
            s.ripPrint("Received #%s but already in rcvdMsgs" % msg.sequence_number)
            return True
        return False
        
    def validateCerts(s,msg):
        return msg.certificate > 0

    def checkSignature(s,msg):
        # if this is an SNN, validate the certificates and save them first, then check the signature
        return msg.signature > 0

    def RIP_FSM(s):
        s.fsm = StateMachine("RIP State Machine")
        s.fsm.addState("CLOSED",
            ("PASSIVE_OPEN","LISTEN"),
            ("SEND_SNN", "SNN-SENT"))
        s.fsm.addState("LISTEN", 
            ("CLOSE","CLOSED"),
            ("SEND_SNN", "SNN-SENT"),
            ("RECV_SNN","SNN-RECV"))
        s.fsm.addState("SNN-SENT", 
            ("CLOSE","CLOSED"),
            ("RECV_SNN","SNN-RECV"),
            ("RECV_SNN_ACK","ESTAB"),
            onEnter = s.sendSNN,
            onExit = s.sendAckOfSNN)
        s.fsm.addState("SNN-RECV", 
            ("ACK_RCVD","ESTAB"),
            ("CLOSE", "CLOSED"),
            onEnter = s.sendAckOfSNN)
        s.fsm.addState("ESTAB", 
            ("RECV_CLOSE","CLOSE-RCVD"),
            ("CLOSE_SENT","CLOSE-REQ"),
            ("RECOVER", "SNN-SENT"),
            onEnter = s.connectionEstablished)
        s.fsm.addState("CLOSE-RCVD", 
            ("CLOSE_ACK_SENT","CLOSED"),
            onEnter = s.finishThenExit,
            onExit = s.sendCloseReqAckAndShutdown)
        s.fsm.addState("CLOSE-REQ", 
            ("CLOSE_ACK_RCVD", "CLOSED"),
            onExit = s.shutdown)
        s.fsm.addState("ERROR-STATE", onEnter = s.killConnection)
        return s.fsm
        
    def startFSM(s): # this gets overwritten by the ServerRIP
        s.fsm.start("CLOSED", "ERROR-STATE")
        s.fsm.signal("SEND_SNN", None)
        
    def connectionEstablished(s, signal, rcvdMsg):
        s.ripPrint("Connection Established")
        s.connectionMade()
        
    def sendSNN(s, signal, _ignore):
        s.ripPrint("Sending SNN")
        msg = RIPMessage()
        s.seqnum = unpack('I', urandom(4))[0]
        while s.seqnum+10000 > 2**32:
            s.seqnum = unpack('I', urandom(4))[0]
        msg.sequence_number = s.seqnum
        msg.sequence_number_notification_flag = True
        msg.certificate = [s.myNonce,s.myCert,s.CAcert]
        msg.sessionID = s.sessionID
        s.sentMsgs[msg.sequence_number] = msg
        s.sendMessage(msg, s.maxRetries)
        
    def sendAckOfSNN(s, signal, rcvdMsg):
        if signal == "CLOSE": return
        s.ripPrint("Sending Ack of SNN")
        msg = RIPMessage()
        msg.acknowledgement_flag = True
        msg.acknowledgement_number = rcvdMsg.sequence_number + 1
        msg.certificate = [format(int(rcvdMsg.certificate[0], 16)+1, 'x')]
        if s.seqnum == 0:
            # Just got an SNN so send an SNN too + ACK (server)
            s.seqnum = unpack('I', urandom(4))[0]
            while s.seqnum+10000 > 2**32:
                s.seqnum = unpack('I', urandom(4))[0]
            msg.sequence_number_notification_flag = True
            s.sentMsgs[s.seqnum] = msg
            msg.certificate = [s.myNonce] + msg.certificate
            msg.certificate = msg.certificate + [s.myCert] + [s.CAcert]
            s.otherCert = rcvdMsg.certificate[1]
            s.otherCA = rcvdMsg.certificate[2]
            retries = s.maxRetries
            s.sentMsgs[msg.sequence_number] = msg
            msg.sequence_number = s.seqnum
            s.seqnum += 1
        else: # we got an SNN+ACK so send just an ACK of SNN (client)
            s.otherCert = rcvdMsg.certificate[2]
            s.otherCA = rcvdMsg.certificate[3]
            retries = 1
            s.lastAckRcvd = max(s.lastAckRcvd, rcvdMsg.acknowledgement_number)
            s.ripPrint("ACK of SNN received. Last ACK# %d" % (s.lastAckRcvd))
            s.connected = True
            msg.sequence_number = s.seqnum - 1
        s.expectedSeq = rcvdMsg.sequence_number + 1
        s.lastAckSent = msg.acknowledgement_number
        s.sessionID = str(s.myNonce) + rcvdMsg.certificate[0]
        msg.sessionID = s.sessionID
        s.sendMessage(msg, s.maxRetries)
        
    def sendAck(s, rcvd):
        s.ripPrint("Sending Ack")
        msg = RIPMessage()
        msg.sequence_number = s.seqnum
        msg.acknowledgement_flag = True
        msg.acknowledgement_number = rcvd.sequence_number + len(rcvd.data)
        s.lastAckSent = msg.acknowledgement_number
        s.ripPrint("ACK check: %s and %s" % (msg.acknowledgement_number , s.lastAckSent))
        msg.sessionID = s.sessionID
        s.sendMessage(msg, s.maxRetries)
        
    def logAndDeconstructFSM(s,signal):
        pass
        
    def finishThenExit(s,signal):
        pass
        
    def sendCloseReqAckAndShutdown(s,signal):
        pass
    
    def shutdown(s, signal):
        s.loseConnection()

    def killConnection(s, signal, _ignore):
        s.connectionLost()
    
    def signMessage(s, msg):
        hasher = SHA256.new()
        hasher.update(msg.__serialize__())
        msg.signature = s.signer.sign(hasher)
        return msg
        
    def ripPrint(s, thestr):
        print("\033[92;1m[RIP] %s \033[0m" % thestr)

class RIPServerProtocol(RIPProtocol):
    def __init__(s):
        super(RIPServerProtocol, s).__init__()

    def startFSM(s):
        s.fsm.start("LISTEN", "ERROR-STATE")

class RIPFactory(StackingFactoryMixin, Factory):
    protocol = RIPProtocol

class RIPServerFactory(RIPFactory):
	protocol = RIPServerProtocol
    
ConnectFactory = RIPFactory
ListenFactory = RIPServerFactory
