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
    sys.path.append("~/Documents/PlayGround/secondtest/src/")
except: print("\033[91mCouldn't find Playground where Fady put it. So you're probably not Fady.\033[0m")

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
from time import clock

from CertFactory import CertFactory as cf

class RIPMessage(MessageDefinition):
    PLAYGROUND_IDENTIFIER = "RIP.RIPMessage"
    MESSAGE_VERSION = "1.0"

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
        #print(" Session ID #\t%s" % msg.sessionID)
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

    def loseConnection(s):
        s.ripP.loseConnection()

class RIPProtocol(StackingProtocolMixin, Protocol):
    def __init__(s):
        s.debug = False
        s.errordebug = True
        s.statusdebug = True

        s.messages = MessageStorage()
        s.OBBuffer = "" # outbound buffer, should prbly be a list
        s.fsm = s.RIP_FSM()
        s.connected = False
        s.sendClose = False # flag to indicate sending loop should send a close
        s.waiting = False
        s.finishing = False
        s.closeRcvd = False
        s.closeSent = False
        s.shuttingDown = False
        
        s.seqnum = 0 # gets set later but this should be the sequence of the next new packet
        s.lastAckRcvd = None # this is the sequence number the other party expects

        s.AckQ = list()
        s.transmitQ = list()
        s.retransmitQ = list()
        
        s.expectedSeq = None # this is the sequence number of the next expected packet
        s.lastAckSent = None # this is what we told the other party we're expecting
        s.rcvdMsgs = dict() # unprocessed rcvdMsgs
        s.deferreds = list() # so we can disable them when shutting down
        
        s.MSS = 2048 # fixed
        s.maxUnAcked = 256
        s.transmitDelay = 0.005
        s.retransmit_delay = 3
        s.maxAttempts = 256 
        s.sessionID = "" # gets set after nonces are exchanged
        s.myNonce = urandom(8).encode('hex') # random hex nonce
        
        s.addr = "new"

        s.otherCerts = None # store the other certs here

        s.ripPrint("RIPProtocol Initialized")
        
        if s.statusdebug:
            s.printStatus()
        
    def makeConnection(s, transport):
        StackingProtocolMixin.__init__(s)
        s.ripT = RIPTransport(transport, s)
        s.transport = s.ripT

        s.addr = transport.getHost().host
        s.ripPrint("Host: " + str(s.addr))
        s.mykey = RSA.importKey(cf.getPrivateKeyForAddr(s.addr))
        s.signer = PKCS1_v1_5.new(s.mykey)
        certFiles = cf.getCertsForAddr(s.addr)
        rootcertfile = cf.getRootCert()
        s.rootcert = rootcertfile
        s.myCert = certFiles[0]
        s.CAcert = certFiles[1]
        s.rootX509 = X509Certificate.loadPEM(rootcertfile)
        s.myX509 = X509Certificate.loadPEM(certFiles[0])
        s.CAX509 = X509Certificate.loadPEM(certFiles[1])

        s.startFSM()

    def connectionMade(s):
        s.makeHigherConnection(s.ripT)
        s.ripPrint("Higher connection made")
        s.sendDataOut()


    # Checks then routes the incoming message to the appropriate parser
    def dataReceived(s,data):
        try:
            s.messages.update(data)
        except:
            s.ripPrintError("MessageStorage update failure")
            # should I reinstntiate?
        #try:
        for msg in s.messages.iterateMessages():
            s.ripPrint("Received #" + str(msg.sequence_number) + " ACK# " + str(msg.acknowledgement_number))
            if s.isDuplicate(msg):
                #s.ripPrintError("Got a duplicate non-ACK message")
                continue # discard this message
            if not s.checkSignature(msg):
                #s.ripPrintError("Signature doesn't match/certs invalid")
                continue # discard this message
            #try:
            if not s.connected: # there must be an FSM way to do this...
                if msg.acknowledgement_flag == True: # is this an ACK of a SNN
                    if msg.sequence_number_notification_flag == True: # and an SNN
                        if "UNSET" not in str(msg.certificate) and int(msg.certificate[1],16) == int(s.myNonce,16)+1: # Check nonce
                            #s.ripPrint("ACK received and updated")
                            s.fsm.signal("RECV_SNN_ACK", msg)
                        else: # it failed the Nonce Check
                            continue # toss it (for now)
                    elif "UNSET" not in str(msg.certificate) and int(msg.certificate[0],16) == int(s.myNonce,16)+1: # this should be just an ACK of an SNN
                        s.connected = True
                        #s.ripPrint("ACK received and updated")
                        s.fsm.signal("ACK_RCVD", msg)
                        s.expectedSeq += 1
                    else: # this ACK failed the Nonce test
                        continue # toss it (for now)
                elif msg.sequence_number_notification_flag == True: # this should be an initial SNN
                    s.fsm.signal("RECV_SNN", msg)
                    #Start recurssive message sender
                    s.sendMessage()
                else: # we're not connected and we didn't get an SNN nor ACK of SNN
                    # we might want to keep this message for later processing but the safest option is to discard it:
                    continue # discard this message
            
            else: # we're already connected
                # Check if an SNN is received (error) and (for now) kill the connection 
                if msg.sequence_number_notification_flag == True:
                    s.fsm.signal("RECV_SNN_AFTER_ESTAB", msg)
                    return
                s.processDataIn(msg)
        #except: s.ripPrintError("Error redirecting incoming message")
            
    def processDataIn(s, msg):
        #try:
            #  Process ACK
            if msg.acknowledgement_flag == True:
                s.lastAckRcvd = max(s.lastAckRcvd, msg.acknowledgement_number)
                s.ripPrint("ACK received and processed (%s)" % s.lastAckRcvd)
                if s.fsm.currentState() == "CLOSE-RQSTD" and s.lastAckRcvd == s.seqnum:
                    s.fsm.signal("CLOSE_ACK_RCVD")
                return
            #s.ripPrint("Processing data in")
            s.rcvdMsgs[msg.sequence_number] = msg
            updateFlag = True
            while updateFlag:
                updateFlag = False
                #s.ripPrint("Looking for expectedSeq # %s in rcvdMsgs (%s)" % (s.expectedSeq,len(s.rcvdMsgs)))
                for prevk in s.rcvdMsgs.keys():
                    prior = s.rcvdMsgs[prevk]
                    # need to add something that will clean up < expected sequence messages
                    if prior.sequence_number == s.expectedSeq:
                        #s.ripPrint("Found the msg, processing...")
                        s.expectedSeq+=max(len(prior.data),0)
                        if prior.close_flag == True:
                            s.closeRcvd = True
                            s.waitToAckClose("Received Close request", prior)
                            #s.fsm.signal("RECV_CLOSE", prior)
                        else:
                            s.sendAck(prior)
                        prior = s.rcvdMsgs.pop(prevk, None)
                        updateFlag = True
                        #if len(prior.data) > 0:
                        s.higherProtocol() and s.higherProtocol().dataReceived(prior.data)
                    elif prior.sequence_number < s.expectedSeq:
                        s.ripPrint("Found an older message??? Removing it....")
                        prior = s.rcvdMsgs.pop(prevk, None)
                        updateFlag = True
        #except: s.ripPrintError("Error with processing incoming message")
    
    def sendMessage(s):
        msg = None
        # First check ACK queue
        if len(s.AckQ) > 0:
            s.ripPrint("Found a queued ACK to send")
            msg = s.AckQ.pop()
            triesLeft = 1
            s.AckQ = list()
        # then see if any initial messages are queued
        # (assuming you've been receiving ACKs)
        elif len(s.transmitQ) > 0 and len(s.retransmitQ) < s.maxUnAcked:
            s.ripPrint("Found a queued message to send")
            msg = s.transmitQ.pop(0)
            triesLeft = s.maxAttempts
            s.retransmitQ.append([s.maxAttempts, clock()+ s.retransmit_delay, msg])
            #msg.printMessageNicely()
            s.ripPrint("Tries Left: %s" % triesLeft)
        elif len(s.retransmitQ) > 0:
            #s.ripPrint("Searching for a retransmit...")
            while len(s.retransmitQ) > 0 and msg == None:
                resend = s.retransmitQ[0]
                #s.ripPrint("Considering retransmit %s" % resend)
                if resend[0] <= 0:
                    s.ripPrintError("PACKET #%s RAN OUT OF RETRIES" % s.resend[2].sequence_number)
                    s.retransmitQ.pop(0)
                elif resend[2].sequence_number < s.lastAckRcvd:
                    # Already ACKed
                    s.retransmitQ.pop(0)
                elif resend[1] > clock():
                    #s.ripPrint("most recent retransmit still needs waiting")
                    break
                else:
                    s.ripPrint("Found a queued retransmit to send")
                    msg = s.retransmitQ.pop(0)[2]
                    triesLeft = resend[0]
                    s.retransmitQ.append([resend[0]-1, clock() + s.retransmit_delay, msg])
        else:
            #s.ripPrint("No messages to send")
            msg = None

        if msg != None:
            # checks to see if the message should be sent
            #s.ripPrint("Want to send # %s  Last ACK Rcvd: %s" % (msg.sequence_number, s.lastAckRcvd))
            msg = s.signMessage(msg)
            # send message
            s.ripPrint("Sending # %s  ACK# %s  triesLeft= %d" % (msg.sequence_number, msg.acknowledgement_number, triesLeft))
            s.ripT.tSend(msg)
            if msg.close_flag == True:
                s.ripPrintError("Close Request Sent")
                if s.closeSent == False:
                    s.fsm.signal("CLOSE_SENT", msg)
        s.deferreds.append( deferLater(reactor, s.transmitDelay, s.sendMessage) )
    
    def processOut(s, data):
        s.OBBuffer += data

    def sendDataOut(s): # recursively sends data with delays to prevent blocking
        bufferSize = len(s.OBBuffer)
        if bufferSize > 0:
            EoB = min(bufferSize, s.MSS)
            dataseg = s.OBBuffer[:EoB]
            s.OBBuffer = s.OBBuffer[EoB:]
            msg = RIPMessage()
            msg.data = dataseg
            msg.sequence_number = s.seqnum
            s.seqnum += max(len(dataseg),1)
            msg.sessionID = s.sessionID
            #s.sendMessage(msg, s.maxAttempts)
            s.transmitQ.append(msg)
            if len(s.OBBuffer) == 0:
                s.ripPrint("Outbound buffer finished")
        
        else:
            if s.sendClose == True and s.waiting == False and s.fsm.currentState() != "CLOSE-RQSTD":
                s.waiting = True
                s.sendCloseReq("Done buffering data. Adding Close Request to queue", None)
        s.deferreds.append( deferLater(reactor, .01, s.sendDataOut) )
        
    
    def isDuplicate(s, msg):
        # should check if the message has already been seen
        if msg.acknowledgement_flag == True:
            ###s.ripPrint("isDuplicate: Letting ACK through")
            return False
        if msg.sequence_number < s.lastAckSent:
            s.ripPrintError("Received #%s but last Ack sent #%s" % (msg.sequence_number, s.lastAckSent))
            s.sendAck(None)
            return True
        if msg.sequence_number in s.rcvdMsgs.keys():
            ###s.ripPrintError("Received #%s but already in rcvdMsgs (%s)" % (msg.sequence_number,len(s.rcvdMsgs)))
            return True
        return False
        
    def certsValid(s,certs): # need to reimplement this in a loop
        try:
            cert = certs[0].getPemEncodedCertWithoutSignatureBlob()
            hasher = SHA256.new()
            hasher.update(cert)
            otherCAPubK = RSA.importKey(certs[1].getPublicKeyBlob())
            rsaVerifier = PKCS1_v1_5.new(otherCAPubK)
            result = rsaVerifier.verify(hasher, certs[0].getSignatureBlob())
            if result:
                cert = certs[1].getPemEncodedCertWithoutSignatureBlob()
                hasher = SHA256.new()
                hasher.update(cert)
                otherCAPubK = RSA.importKey(s.rootX509.getPublicKeyBlob())
                rsaVerifier = PKCS1_v1_5.new(otherCAPubK)
                result = rsaVerifier.verify(hasher, certs[1].getSignatureBlob())
            return result
        except:
            s.ripPrintError("Error Validating Certs. Assuming failure")
            return False

    def checkSignature(s,msg):
        # if this is an SNN, validate the certificates and save them first, then check the signature
        try:
            if msg.sequence_number_notification_flag == True: #certs are in the message
                # we need to be able to deal with multiple 
                if len(msg.certificate) == 3: i = 1
                else: i = 2
                certs = [X509Certificate.loadPEM(certF) for certF in msg.certificate[i:]]
                if not s.certsValid(certs):
                    s.ripPrintError("Certs failed validation")
                    return False
            else:
                certs = [X509Certificate.loadPEM(certF) for certF in s.otherCerts]

            signature = msg.signature
            msg.signature = ""
            otherPubK = RSA.importKey(certs[0].getPublicKeyBlob())
            rsaVerifier = PKCS1_v1_5.new(otherPubK)
            hasher = SHA256.new()
            hasher.update(msg.__serialize__())
            result = rsaVerifier.verify(hasher, signature)
            if not result: s.ripPrintError("Signature incorrect")
            return result
        except Exception:
            s.ripPrintError(str(Exception))
            s.ripPrintError("Error checking signature. Assuming failed")
            return False

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
            ("CLOSE_SENT","CLOSE-RQSTD"),
            ("RECOVER", "SNN-SENT"),
            onEnter = s.connectionEstablished)
        s.fsm.addState("CLOSE-RCVD", 
            ("CLOSE_SENT","CLOSED"),
            ("CLOSE_ACK_SENT","CLOSED"),
            onEnter = s.sendCloseReqAckAndShutdown,
            onExit = s.shutdown)
        s.fsm.addState("CLOSE-RQSTD", 
            ("RECV_CLOSE","CLOSED"),
            ("CLOSE_ACK_RCVD", "CLOSED"),
            ("TIMEOUT_CLOSE_ACK", "CLOSED"),
            onEnter = s.callWaitForAck,
            onExit = s.shutdown)
        s.fsm.addState("ERROR-STATE", onEnter = s.killConnection)
        return s.fsm
        
    def startFSM(s): # this gets overwritten by the ServerRIP
        s.fsm.start("CLOSED", "ERROR-STATE")
        s.fsm.signal("SEND_SNN", None)
        #Start recurssive message sender
        s.sendMessage()
        
    def connectionEstablished(s, signal, rcvdMsg):
        s.lastAckRcvd = max(s.lastAckRcvd, rcvdMsg.acknowledgement_number)
        s.ripPrint("Connection Established")
        s.connectionMade()
        
    def sendSNN(s, signal, _ignore):
        s.ripPrint("Sending SNN")
        msg = RIPMessage()
        s.seqnum = unpack('I', urandom(4))[0]
        while s.seqnum+10000 > 2**32:
            s.seqnum = unpack('I', urandom(4))[0]
        msg.sequence_number = s.seqnum
        s.seqnum += 1
        msg.sequence_number_notification_flag = True
        msg.certificate = [s.myNonce,s.myCert,s.CAcert]
        msg.sessionID = s.sessionID
        #s.sendMessage(msg, s.maxAttempts)
        s.transmitQ.append(msg)
        
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
            msg.certificate = [s.myNonce] + msg.certificate
            msg.certificate = msg.certificate + [s.myCert] + [s.CAcert]
            s.otherCerts = rcvdMsg.certificate[1:]
        else: # we got an SNN+ACK so send just an ACK of SNN (client)
            s.otherCerts = rcvdMsg.certificate[2:]
            s.lastAckRcvd = max(s.lastAckRcvd, rcvdMsg.acknowledgement_number)
            s.ripPrint("Responding with just and ACK# %d" % (s.lastAckRcvd))
            s.connected = True
        msg.sequence_number = s.seqnum
        s.seqnum += 1
        s.expectedSeq = msg.acknowledgement_number
        s.lastAckSent = msg.acknowledgement_number
        s.sessionID = str(s.myNonce) + rcvdMsg.certificate[0]
        msg.sessionID = s.sessionID
        #s.sendMessage(msg, s.maxAttempts)
        s.transmitQ.append(msg)
        
    def sendAck(s, rcvd):
        #s.ripPrint("Sending Ack")
        msg = RIPMessage()
        msg.sequence_number = s.seqnum
        msg.acknowledgement_flag = True
        #msg.acknowledgement_number = rcvd.sequence_number + len(rcvd.data)
        msg.acknowledgement_number = s.expectedSeq
        s.lastAckSent = msg.acknowledgement_number
        msg.sessionID = s.sessionID
        #s.sendMessage(msg, 1)
        s.AckQ.append(msg)
    
    def callWaitForAck(s, signal, rcvd):
        s.deferreds.append( deferLater(reactor, 120, s.fsm.signal, "TIMEOUT_CLOSE_ACK", None) )
        s.waitForCloseAck(signal, rcvd)

    def waitForCloseAck(s, signal, rcvd):
        s.closeSent = True
        if s.lastAckRcvd != s.seqnum and s.closeRcvd == False:
            s.ripPrintError("Waiting for Close ACK")
            s.deferreds.append( deferLater(reactor, .5, s.waitForCloseAck, signal, rcvd) )
        else:
            s.fsm.signal("CLOSE_ACK_RCVD")
        
    def waitToAckClose(s, signal, rcvd):
        s.closeRcvd = True
        if s.isNotDone() and s.closeSent == False:
            s.ripPrintError("Waiting before ACKing close")
            s.deferreds.append( deferLater(reactor, .5, s.waitToAckClose, signal, rcvd) )
        else:
            s.fsm.signal("RECV_CLOSE", rcvd)

    def sendCloseReqAckAndShutdown(s,signal,rcvd):
        s.ripPrintError("Sending close ACK")
        s.sendAck(rcvd)
        s.fsm.signal("CLOSE_ACK_SENT", rcvd)
    
    def shutdown(s, signal, msg):
        s.ripPrintError("\033[91mShutting down: %s \033[0m" % signal)
        for d in s.deferreds:
            d.cancel()
        try:
            s.higherProtocol().connectionLost()
        except: s.ripPrintError("Shutdown unable to call higher protocol")
        s.ripPrint("Shut down complete!")

    def killConnection(s, signal, _ignore):
        #s.connectionLost("Kill command")
        pass

    def loseConnection(s):
        s.ripPrintError("Lose Connection called")
        #s.higherProtocol().connectionLost()
        s.sendClose = True

    def connectionLost(s, reason):
        # called when connection is lost, should keep processing
        if s.isNotDone():
            s.ripPrintError("connectionLost but still processing (%s rcvdMsgs)" % len(s.rcvdMsgs))
            s.deferreds.append(deferLater(reactor, .5, s.connectionLost, reason))
        else:
            s.ripPrintError("connectionLost: calling shutdown()")
            s.shutdown(reason, None)

    def close(s):
        s.ripPrintError("Recevied Close command")
        s.loseConnection()

    def sendCloseReq(s,signal, _ignore):
        s.ripPrintError("Adding close request to queue")
        msg = RIPMessage()
        msg.sequence_number = s.seqnum
        s.seqnum += 1
        msg.close_flag = True
        msg.sessionID = s.sessionID
        #s.sendMessage(msg, s.maxAttempts)
        s.transmitQ.append(msg)
        s.deferreds.append( deferLater(reactor, 120, s.fsm.signal, "TIMEOUT_CLOSE_ACK", None) )

    def isNotDone(s): # checks if msgs still need to be sent, confirmed, or rcvd
        return  len(s.OBBuffer) > 0 or s.lastAckRcvd < s.seqnum or len(s.rcvdMsgs) > 0 or len(s.AckQ) > 0 or len(s.transmitQ) > 0 #or len(s.retransmitQ) > 0

    def signMessage(s, msg):
        msg.signature = ""
        hasher = SHA256.new()
        hasher.update(msg.__serialize__())
        msg.signature = s.signer.sign(hasher)
        return msg
        
    def ripPrint(s, thestr):
        if s.debug:
            print("\033[95;1m[RIP %s]\033[92m %s\033[0m" % (s.addr,thestr))

    def ripPrintError(s, thestr):
        if s.errordebug:
            print("\033[95;1m[RIP %s]\033[91m %s\033[0m" % (s.addr,thestr))

    def printStatus(s):
        print("\033[95;1m[RIP %s]\033[93m rMs=%s   AckQ=%s   tQ=%s   rtQ=%s   seq=%s   lAck=%s   OB=%s\033[0m" % (s.addr, len(s.rcvdMsgs),len(s.AckQ),len(s.transmitQ), len(s.retransmitQ),s.seqnum,s.lastAckRcvd,len(s.OBBuffer)))
        s.deferreds.append( deferLater(reactor, 1, s.printStatus))

class RIPServerProtocol(RIPProtocol):
    def __init__(s):
        super(RIPServerProtocol, s).__init__()

    def startFSM(s):
        s.fsm.start("LISTEN", "ERROR-STATE") 

    def ripPrint(s, thestr):
        if s.debug:
            print("\033[94;40;1m[RIP %s]\033[92m %s\033[0m" % (s.addr,thestr))

    def ripPrintError(s, thestr):
        if s.errordebug:
            print("\033[94;40;1m[RIP %s]\033[91m %s\033[0m" % (s.addr,thestr))

    def printStatus(s):
        print("\033[94;40;1m[RIP %s]\033[93m rMs=%s   AckQ=%s   tQ=%s   rtQ=%s   seq=%s   lAck=%s   OB=%s\033[0m" % (s.addr, len(s.rcvdMsgs),len(s.AckQ),len(s.transmitQ), len(s.retransmitQ),s.seqnum,s.lastAckRcvd,len(s.OBBuffer)))
        s.deferreds.append( deferLater(reactor, 1, s.printStatus))

class RIPFactory(StackingFactoryMixin, Factory):
    protocol = RIPProtocol

class RIPServerFactory(RIPFactory):
	protocol = RIPServerProtocol
    
ConnectFactory = RIPFactory
ListenFactory = RIPServerFactory