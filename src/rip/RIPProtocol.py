'''
Implementation of The Reliable Interaction Protocol (RIP)
as drafted by JHU's Fall 2016 Network Security class's PETF
Transport Layer on the Playground network
Implemented using Twisted 16.4.1

Author: Fady Barsoum
Created: 02OCT2016 1:05AM
Last Modified: 12OCT2016 11:23AM
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

    BODY = [(        "sequence_number", UINT4),
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
        self.lowerTransport().write(ptMessage.__serialize__())

class RIPProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):
        self.messages = MessageStorage()
        self.buffer = ""

    def connectionMade(self):
        higherTransport = RIPTransport(self.transport)
        self.makeHigherConnection(higherTransport)

    def dataReceived(self,data):
        self.messages.update(data)
        for message in self.messages.iterateMessages():
            pass # process the message

class RIPFactory(StackingFactoryMixin, Factory):
    protocol = RIPProtocol
    
class RIPStateMachine(StateMachine):
    def __init__(self, initiator):
        pass
	
ConnectFactory = RIPFactory
ListenFactory = RIPFactory
