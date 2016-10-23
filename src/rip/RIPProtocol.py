'''
Implementation of The Reliable Interaction Protocol (RIP)
Transport Layer on the Playground network

As drafted by JHU's Fall 2016 Network Security class's PETF
Implemented using Twisted 16.4.1

Author: Fady Barsoum
Created: 02OCT2016 1:05AM
'''

import sys
sys.path.append("/home/fady/Documents/PlayGround/firsttest/src/")
import playground
from playground.network.common.Protocol import StackingTransport, StackingProtocolMixin, StackingFactoryMixin
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import UINT4, OPTIONAL, STRING, DEFAULT_VALUE, LIST, BOOL1
import playground.network.common.Protocol.MessageStorage
import playground.network.common.statemachine.StateMachine

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor

import pyopenssl
from os import urandom
from struct import unpack

class RIPMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RIP.RIPMessage"
    MESSAGE_VERSION = "1.1"

    BODY = [("sequence_number", UINT4),
            ("acknowledgement_number", UINT4, OPTIONAL),
            ("segment_number", UNIT4, OPTIONAL),
            ("signature", STRING, DEFAULT_VALUE("")),
            ("certificate", LIST(STRING), OPTIONAL),
            ("sessionID", STRING),
            ("window_size", UNIT1, OPTIONAL),
            ("maximum_segment_size", UNIT4, OPTIONAL),
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
        self.fsm = self.RIP_FSM()
        self.fsm.start("CLOSED")
        
        self.seqnum = unpack(urandom(4))[0]
        self.lastAckRcvd = None
        self.sentMsgs = dict() # do not retransmit ACKs!!
        
        self.expectedSeq = None
        self.lastAckSent = None
        self.rcvdMsgs = dict()
        self.deferreds = list()
        
        self.MSS = 4096
        self.retransmit_delay = 10.0
        self.maxRetries = 3
        self.otherCert = None
        self.otherMSS = None
        
    def makeConnection(self, transport):
        StackingProtocolMixin.__init__(self, transport)
        self.fsm.signal("ACTIVE_OPEN")

    def connectionMade(self):
        self.ripT = RIPTransport(self.transport)
        self.makeHigherConnection(self.ripT)

    def dataReceived(self,data):
        self.messages.update(data)
        for msg in self.messages.iterateMessages():
            if self.duplicate(msg):
                print("Got a duplicate")
                continue
            if not self.validateCerts(msg):
                print("Certs failed validation")
                continue
            if not self.checkSignature(msg):
                print("Signature doesn't match")
                continue
            try:
                if msg.sequence_number_notification_flag:
                    if msg.acknowledgement_flag:
                        self.fsm.signal("RECV_SNN_ACK", msg)
                    else:
                        self.fsm.signal("RECV_SNN", msg)
            except: print("No seqflag or ack flag")
            try:
                if msg.close_flag:
                    if msg.acknowledgement_flag:
                        self.fsm.signal("CLOSE_ACK_RCVD")
                    else:
                        self.fsm.signal("RECV_CLOSE")
            except: print("Something with closed flags happened")
            try:
                rcvdMsgs[msg.sequence_number] = msg
                updateFlag = True
                while updateFlag:
                    updateFlag = False
                    for prev in rcvdMsgs:
                        prior = rcvdMsgs[prev]
                        if prior.sequence_number == self.expectedSeq:
                            prior = rcvdMsgs.pop(prev)
                            updateFlag = True
                            self.expectedSeq+=1
                            if len(prior.data) > 0:
                                self.higherProtocol() and self.higherProtocol().dataReceived(prior.data)
            except: print("Something with transferring data up")
    
    def sendMessage(self, msg, triesLeft):
        # checks to see if the message should be sent
        if not msg.acknowledgement_flag and msg.sequence_number <= self.lastAckRcvd:
            self.sentMsgs.pop(msg.sequence_number)
            return
        if triesLeft <= 0:
            # we should kill this connection
            self.sentMsgs.pop(msg.sequence_number)
            return
        # send message
        self.ripT.tSend(msg)
        # callback for retransmit
        self.deferreds.append( deferLater(reactor, self.retransmit_delay, self.sendMessage, msg, triesLeft-1) )
    
    def processOut(self, data):
        self.OBBuffer += data
        bufferSize = len(OBBuffer)
        while bufferSize > 0:
            bufferSize = len(OBBuffer)
            EoB = min(bufferSize, self.otherMSS)
            msg = RIPMessage()
            dataseg = OBBuffer[:EoB]
            OBBuffer = OBBuffer[EoB:]
            msg.data = dataseg
            msg.acknowledgement_number = self.seqnum
            self.seqnum += 1
            # other msg stuff
            
    
    def duplicate(self, msg):
        return msg.sequence_number <= self.lastAckSent or msg.sequence_number in rcvdMsgs.keys()
        
    def validateCerts(self,msg):
        return msg.certificate > 0

    def checkSignature(self,msg):
        return msg.signature > 0

    def RIP_FSM(self):
        self.fsm = StateMachine("RIP State Machine")
        self.fsm.addState("CLOSED", [
            ("PASSIVE_OPEN","LISTEN"),
            ("ACTIVE_OPEN", "SNN-SENT")])
        self.fsm.addState("LISTEN", [
            ("CLOSE","CLOSED"),
            ("SEND_SNN", "SNN-SENT"),
            ("ACTIVE_OPEN", "SNN-SENT"),
            ("RECV_SNN","SNN-RECV")])
        self.fsm.addState("SNN-SENT", [
            ("CLOSE","CLOSED"),
            ("RECV_SNN","SNN-RECV"),
            ("RECV_SNN_ACK","ESTAB")],
            onEnter = self.sendSNN)
        self.fsm.addState("SSN-RECV", [
            ("RECV_AWK_of_SNN","ESTAB")],
            onEnter = self.sendAWKofSNN})
        self.fsm.addState("ESTAB", [
            ("RECV_CLOSE","CLOSE-RCVD"),
            ("CLOSE_SENT","CLOSE-REQ"),
            ("REVOC", "SNN-SENT")],
            onEnter = self.connectionEstablished)
        self.fsm.addState("CLOSE-RCVD", [
            ("CLOSE_ACK_SENT","CLOSED")],
            onEnter = finishThenExit,
            onExit = self.sendCloseReqAckAndShutDown)
        self.fsm.addState("CLOSE-REQ", [
            ("CLOSE_ACK_RCVD", "CLOSED")],
            onExit = self.shutdown)
        return self.fsm
        
    def connectionEstablished(self, signal):
        self.connectionMade(self)
        
    def sendAWKofSNN(self, signal):
        pass

    def sendSNN(self, signal):
        pass
    
    def logAndDeconstructFSM(self):
        pass

    def signMessage(self, msg):
        msg.certificate = ["blah"]

class RIPFactory(StackingFactoryMixin, Factory):
    protocol = RIPProtocol


	
ConnectFactory = RIPFactory
ListenFactory = RIPFactory
