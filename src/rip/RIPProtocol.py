'''
Implementation of The Reliable Interaction Protocol (RIP)
Transport Layer on the Playground network

As drafted by JHU's Fall 2016 Network Security class's PETF
Implemented using Twisted 16.4.1

Author: Fady Barsoum
Created: 02OCT2016 1:05AM
Last Modified: 12OCT2016 3:59PM
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

class RIPMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RIP.RIPMessage"
    MESSAGE_VERSION = "1.0"

    BODY = [(        "sequence_number", UINT4         ),
            ( "acknowledgement_number", UINT4,        OPTIONAL),
            (              "signature", STRING,       DEFAULT_VALUE("")),
            (            "certificate", LIST(STRING), OPTIONAL),
            (   "acknowledgement_flag", BOOL1,        DEFAULT_VALUE(False)),
            (             "close_flag", BOOL1,        DEFAULT_VALUE(False)),
 ( "sequence_number_notification_flag", BOOL1,        DEFAULT_VALUE(False)),
            (             "reset_flag", BOOL1,        DEFAULT_VALUE(False)),
            (                   "data", STRING,       DEFAULT_VALUE("")),
            (                "OPTIONS", LIST(STRING), OPTIONAL)
           ]
    
class RIPTransport(StackingTransport):
    def __init__(self, lowerTransport):
        StackingTransport.__init__(self, lowerTransport)

    def write(self, data):
        ripMessage = RIPMessage()
        ripMessage.data = data
        self.lowerTransport().write(ripMessage.__serialize__())

class RIPProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):
        self.messages = MessageStorage()
        self.fsm = self.RIP_FSM()

    def connectionMade(self):
        higherTransport = RIPTransport(self.transport)
        self.makeHigherConnection(higherTransport)

    def dataReceived(self,data):
        self.messages.update(data)
        for msg in self.messages.iterateMessages():
            if self.validateCerts(msg) and self.checkSignature(msg):
                if self.notDuplicate(msg):
                    if msg.sequence_number_notification_flag:
                        self.fsm.signal("SNN_RECV", msg)


    def validateCerts(self,msg):
        return msg.certificate > 0

    def checkSignature(self,msg):
        return msg.signature > 0

    def RIP_FSM(self):
        self.fsm = StateMachine("RIP State Machine")
        self.fsm.addState("CLOSED", [
            ("PASSIVE_OPEN","LISTEN"),
            ("ACTIVE_OPEN", "SNN-SENT")],
            onEnter = logAndDeconstructFSM)
        self.fsm.addState("SNN-SENT", [
            ("CLOSE","CLOSED"),
            ("RECV_SNN","SNN-RECV")])
        self.fsm.addState("LISTEN", [
            ("CLOSE","CLOSED"),
            ("SEND_SNN", "SNN-SENT"),
            ("RECV_SNN","SNN-RECV")])
        self.fsm.addState("SSN-RECV", [
            ("RECV_AWK_of_SNN","ESTAB")],
            onEnter = sendAWKofSNN})
        self.fsm.addState("ESTAB", [
            ("RECV_RCOVR","SNN-SENT")])
        return self.fsm

    def sendAWKofSNN(self, signal, data):


class RIPFactory(StackingFactoryMixin, Factory):
    protocol = RIPProtocol


	
ConnectFactory = RIPFactory
ListenFactory = RIPFactory
