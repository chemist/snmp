{-# LANGUAGE OverloadedStrings #-}
module Network.Protocol.Snmp 
-- ^ Types
( PDU(..)
, Request(..)
, Value(..)
, ClientException(..)
, OID
, Suite(..)
, Coupla(..)
, Pack(..)
, Version(..)
, SnmpPacket(..)
, Header(..)
, RequestId(..)
-- ^ Second version
, Community(..)
-- ^ Third version
, HeaderData
, ContextEngineID(..)
, ContextName(..)
, ScopedPDU(..)
, MsgID(..)
, MsgFlag
, MsgMaxSize(..)
, MsgSecurityModel
, MsgSecurityParameter
, Reportable
, PrivAuth(..)
-- ^ setters
, setVersion
, setMsgId
, setMaxSize
, setReportable
, setRid
, setPrivAuth
, setPDU
, setUserName
, setAuthenticationParameters
, setFlag
-- ^ getters
, getRid
, getEngineId
, getErrorStatus
, getSuite
-- ^ aliases
, V2Packet
, V3Packet
, OIDS
) 
where

import Network.Protocol.Snmp.Types
import Network.Protocol.Snmp.Version2
import Network.Protocol.Snmp.Version3 
import Control.Lens
import Data.ByteString (ByteString)

type V2Packet = SnmpPacket (Header Community) PDU
type V3Packet = SnmpPacket (Header HeaderData) ScopedPDU

type OIDS = [OID]

getEngineId :: V3Packet -> ContextEngineID
getEngineId v = v ^. body . contextEngineId

getVersion :: SnmpPacket (Header a0) b0 -> Version
getVersion = (^. header . version)

getErrorStatus :: V3Packet -> Integer
getErrorStatus v = v ^. body . pdu . request . es

getRid :: V3Packet -> Integer
getRid v = v ^. body . pdu . request . rid 

getSuiteFromPdu :: PDU -> Suite
getSuiteFromPdu = (^. suite)

getBody :: SnmpPacket a b -> b
getBody = (^. body)

class HasPDU a where
    getPDU :: a -> PDU

instance HasPDU ScopedPDU where
    getPDU (ScopedPDU _ _ p) = p

instance HasPDU PDU where
    getPDU = id

getSuite :: HasPDU b => SnmpPacket a b -> Suite
getSuite x = getSuiteFromPdu $ getPDU (getBody x)

setMaxSize :: MsgMaxSize -> V3Packet -> V3Packet
setMaxSize = (header . headerData . msgMaxSize .~ )

setMsgId :: MsgID -> V3Packet -> V3Packet
setMsgId = (header . headerData . msgId .~ )

setReportable :: Reportable -> V3Packet -> V3Packet
setReportable = (header . headerData . msgFlag . reportable .~ )

setPrivAuth :: PrivAuth -> V3Packet -> V3Packet
setPrivAuth = (header . headerData . msgFlag . privAuth .~)

-- setRid :: RequestId -> SnmpPacket (Header HeaderData) b0 -> SnmpPacket (Header HeaderData) b0
setRid = (body . pdu . request . rid .~)

setVersion :: Version -> SnmpPacket (Header HeaderData) b0 -> SnmpPacket (Header HeaderData) b0
setVersion = (header . version .~ )

setPDU = (body . pdu .~)

setUserName :: ByteString -> V3Packet -> V3Packet
setUserName = (header . headerData . msgSecurityParameter . msgUserName .~)

setAuthenticationParameters :: ByteString -> V3Packet -> V3Packet
setAuthenticationParameters = (header . headerData . msgSecurityParameter . msgAuthenticationParameters .~)

setFlag :: MsgFlag -> V3Packet -> V3Packet
setFlag = (header . headerData . msgFlag .~)



