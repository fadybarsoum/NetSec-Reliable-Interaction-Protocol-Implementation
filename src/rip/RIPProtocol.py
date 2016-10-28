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
except: print("Couldn't find Playground where Fady put it. So you're probably not Fady.")

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

from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

from os import urandom
from struct import unpack

import CertFactory as cf

class RIPMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RIP.RIPMessage"
    MESSAGE_VERSION = "1.1"

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
    
class RIPTransport(StackingTransport):
    def __init__(self, lowerTransport, ripproto):
        StackingTransport.__init__(self, lowerTransport)
        self.ripP = ripproto
        
    def write(self, data):
        ripMessage = self.ripP.processOut(data)
    
    def tSend(self, ripMessage):
        self.lowerTransport().write(ripMessage.__serialize__())

class RIPProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):
        self.messages = MessageStorage()
        self.OBBuffer = "" # outbound buffer, should prbly be a list
        self.fsm = self.RIP_FSM()
        self.fsm.start("CLOSED")
        self.connected = False
        
        self.seqnum = 0 # gets set later
        self.lastAckRcvd = None 
        self.sentMsgs = dict() # do not retransmit ACKs!!
        
        self.expectedSeq = None
        self.lastAckSent = None
        self.rcvdMsgs = dict()
        self.deferreds = list()
        
        addr = self.transport.getHost()
        self.ripPrint("Host: " + str(addr))
        self.mykey = RSA.importKey(cf.getPrivateKeyForAddr(addr))
        self.signer = PKCS1_v1_5.new(self.mykey)
        certFiles = cf.getCertsForAddr(addr)
        rootcertfile = cf.getRootCert()
        self.rootcert = X509Certificate.loadPEM(rootcertfile)
        self.myCert = X509Certificate.loadPEM(certFiles[0])
        self.CAcert = X509Certificate.loadPEM(certFiles[1])
        
        self.MSS = 2048
        self.retransmit_delay = 0.8
        self.maxRetries = 60
        self.sessionID = "notsetyet"
        self.myNonce = urandom(8).encode('hex')
        
        self.otherCert = None
        self.otherCA = None
        
    def makeConnection(self, transport):
        StackingProtocolMixin.__init__(self)
        self.ripT = RIPTransport(transport, self)
        self.fsm.signal("SEND_SNN", transport)

    def connectionMade(self):
        self.makeHigherConnection(self.ripT)

    def dataReceived(self,data):
        self.messages.update(data)
        for msg in self.messages.iterateMessages():

            if self.isDuplicate(msg):
                self.ripPrint("Got a duplicate")
                continue
            if not self.checkSignature(msg):
                self.ripPrint("Signature doesn't match")
                continue
            #try:
            if str(msg.sequence_number_notification_flag) != "UNSET MESSAGE VALUE" and msg.sequence_number_notification_flag:
                if str(msg.acknowledgement_flag) != "UNSET MESSAGE VALUE" and msg.acknowledgement_flag:
                    self.fsm.signal("RECV_SNN_ACK", msg)
                else:
                    self.fsm.signal("RECV_SNN", msg)
            #except: self.ripPrint("No seqflag or ack flag")
            try:
                if str(msg.close_flag) != "UNSET MESSAGE VALUE" and msg.close_flag:
                    if str(msg.acknowledgement_flag) != "UNSET MESSAGE VALUE" and msg.acknowledgement_flag:
                        self.fsm.signal("CLOSE_ACK_RCVD", msg)
                    else:
                        self.fsm.signal("RECV_CLOSE", msg)
            except: self.ripPrint("Error with closed flags happened")
            self.processIn(msg)
            
    def processIn(self, msg):
    #try:
        self.rcvdMsgs[msg.sequence_number] = msg
        updateFlag = True
        while updateFlag:
            updateFlag = False
            for prev in self.rcvdMsgs.keys():
                prior = self.rcvdMsgs[prev]
                if prior.sequence_number == self.expectedSeq:
                    prior = self.rcvdMsgs.pop(prev)
                    updateFlag = True
                    self.expectedSeq+=len(prior.data)+1
                    if len(prior.data) > 0:
                        self.higherProtocol() and self.higherProtocol().dataReceived(prior.data)
                        self.sendAck()
                    if str(prior.acknowledgement_flag) != "UNSET MESSAGE VALUE" and prior.acknowledgement_flag:
                        self.lastAckRcvd = max(self.lastAckRcvd, prior.acknowledgement_number)
                        self.ripPrint("ACK received")
                        if not self.connected:
                            self.fsm.signal("ACK_RCVD",prior)
                            self.connected = True
                    
    #except: self.ripPrint("Error with transferring data up")
    
    def sendMessage(self, msg, triesLeft):
        # checks to see if the message should be sent
        if msg.sequence_number <= self.lastAckRcvd:
            self.sentMsgs.pop(msg.sequence_number)
            return
        if triesLeft <= 0:
            # we should kill this connection
            self.sentMsgs.pop(msg.sequence_number)
            return
        # send message
        self.ripT.tSend(msg)
        # callback for retransmit unless it's a non-SNN, non-Close ACK
        if msg.sequence_number_notification_flag or msg.close_flag or not msg.acknowledgement_flag:
            self.deferreds.append( deferLater(reactor, self.retransmit_delay, self.sendMessage, msg, triesLeft-1) )
    
    def processOut(self, data):
        self.OBBuffer += data
        bufferSize = len(self.OBBuffer)
        while bufferSize > 0:
            bufferSize = len(self.OBBuffer)
            EoB = min(bufferSize, self.otherMSS)
            dataseg = self.OBBuffer[:EoB]
            self.OBBuffer = self.OBBuffer[EoB:]
            msg = RIPMessage()
            msg.data = dataseg
            msg.sequence_number = self.seqnum
            self.seqnum += len(dataseg)+1
            msg = self.signMessage(msg)
            msg.sessionID = self.sessionID
            self.sendMessage(msg, self.maxRetries)
    
    def isDuplicate(self, msg):
        return msg.sequence_number < self.lastAckSent or msg.sequence_number in self.rcvdMsgs.keys()
        
    def validateCerts(self,msg):
        return msg.certificate > 0

    def checkSignature(self,msg):
        return msg.signature > 0

    def RIP_FSM(self):
        self.fsm = StateMachine("RIP State Machine")
        self.fsm.addState("CLOSED",
            ("PASSIVE_OPEN","LISTEN"),
            ("SEND_SNN", "SNN-SENT"))
        self.fsm.addState("LISTEN", 
            ("CLOSE","CLOSED"),
            ("SEND_SNN", "SNN-SENT"),
            ("RECV_SNN","SNN-RECV"))
        self.fsm.addState("SNN-SENT", 
            ("CLOSE","CLOSED"),
            ("RECV_SNN","SNN-RECV"),
            ("RECV_SNN_ACK","ESTAB"),
            onEnter = self.sendSNN,
            onExit = self.sendAckOfSNN)
        self.fsm.addState("SNN-RECV", 
            ("ACK_RCVD","ESTAB"),
            ("CLOSE", "CLOSED"),
            onEnter = self.sendAckOfSNN)
        self.fsm.addState("ESTAB", 
            ("RECV_CLOSE","CLOSE-RCVD"),
            ("CLOSE_SENT","CLOSE-REQ"),
            ("RECOVER", "SNN-SENT"),
            onEnter = self.connectionEstablished)
        self.fsm.addState("CLOSE-RCVD", 
            ("CLOSE_ACK_SENT","CLOSED"),
            onEnter = self.finishThenExit,
            onExit = self.sendCloseReqAckAndShutdown)
        self.fsm.addState("CLOSE-REQ", 
            ("CLOSE_ACK_RCVD", "CLOSED"),
            onExit = self.shutdown)
        return self.fsm
        
    def connectionEstablished(self, signal, rcvdMsg):
        self.ripPrint("Connection Established")
        self.connectionMade()
        
    def sendSNN(self, signal, transport):
        self.ripPrint("Sending SNN")
        msg = RIPMessage()
        self.seqnum = unpack('I', urandom(4))[0]
        while self.seqnum+10000 > 2**32:
            self.seqnum = unpack('I', urandom(4))[0]
        msg.sequence_number = self.seqnum
        msg.sequence_number_notification_flag = True
        msg.certificate = [self.myNonce,self.myCert,self.CAcert]
        msg.sessionID = self.sessionID
        msg = self.signMessage(msg)
        self.sentMsgs[msg.sequence_number] = msg
        self.sendMessage(msg, self.maxRetries)
        
    def sendAckOfSNN(self, signal, rcvdMsg):
        if signal == "CLOSE": return
        self.ripPrint("Sending Ack of SNN")
        msg = RIPMessage()
        msg.acknowledgement_flag = True
        msg.acknowledgement_number = rcvdMsg.sequence_number + 1
        msg.certificate = [hex(int(rcvdMsg.certificate[0], 16)+1)]
        if self.seqnum == 0:
            #send SNN too
            self.seqnum = unpack('I', urandom(4))[0]
            while self.seqnum+10000 > 2**32:
                self.seqnum = unpack('I', urandom(4))[0]
            msg.sequence_number_notification_flag = True
            self.sentMsgs[self.seqnum] = msg
            msg.certificate.insert(0, self.myNonce)
            msg.certificate.extend(self.myCerts)
            self.otherCert = rcvdMsg.certificate[1]
            self.otherCA = rcvdMsg.certificate[2]
        else:
            self.otherCert = rcvdMsg.certificate[1]
            self.otherCA = rcvdMsg.certificate[2]
        msg.sequence_number = self.seqnum
        self.expectedSeq = rcvdMsg.sequence_number + 1
        self.lastAckSent = rcvdMsg.sequence_number + 1
        self.sendMessage(msg, self.maxRetries)
        
    def sendAck(self):
        self.ripPrint("Sending Ack")
        msg = RIPMessage()
        msg.sequence_number = self.seqnum
        msg.acknowledgement_flag = True
        msg.acknowledgement_number = self.expectedSeq
        self.lastAckSent = self.expectedSeq - 1
        msg.sessionID = self.sessionID
        self.sendMessage(msg, self.maxRetries)
        
    def logAndDeconstructFSM(self,signal):
        pass
        
    def finishThenExit(self,signal):
        pass
        
    def sendCloseReqAckAndShutdown(self,signal):
        pass
    
    def shutdown(self, signal):
        self.loseConnection()
    
    def signMessage(self, msg):
        hasher = SHA256.new()
        hasher.update(msg)
        msg.signature = rsaSigner.sign(hasher)
        return msg
        
    def ripPrint(self, thestr):
        print("[RIP] %s" % thestr)

class RIPFactory(StackingFactoryMixin, Factory):
    protocol = RIPProtocol


	
ConnectFactory = RIPFactory
ListenFactory = RIPFactory
