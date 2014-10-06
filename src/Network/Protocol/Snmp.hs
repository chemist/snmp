{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Network.Protocol.Snmp 
-- ^ Types
( PDU
, Request(..)
, Value(..)
, ClientException(..)
, OID
, Suite(..)
, Coupla(..)
, Pack(..)
, Version(..)
, Packet
, Header
, RequestId
-- ^ Second version
, Community(..)
-- ^ Third version
, ContextEngineID(..)
, ContextName(..)
, VersionedPDU
, ID(..)
, Flag
, MaxSize(..)
, SecurityModel
, SecurityParameter
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
, setCommunity
, setSuite
, setRequest
-- -- ^ getters
, getRid
, getEngineId
, getVersion
, getErrorStatus
, getSuite
-- ^ aliases
, OIDS
-- ^ helpers
, initial
) 
where

import Network.Protocol.Snmp.Types
import Data.ByteString (ByteString)
import Data.Monoid (mempty)

type OIDS = [OID]

setVersion :: Version -> Packet -> Packet
setVersion v Packet{..} = case header of
                               HeaderV2{..} -> Packet (header { version = v }) body
                               HeaderV3{..} -> Packet (header { version = v }) body

getEngineId :: Packet -> ContextEngineID
getEngineId Packet{..} = contextEngineId body 

getVersion :: Packet -> Version
getVersion Packet{..} = version header

getErrorStatus :: Packet -> Integer
getErrorStatus Packet{..} = es . request . pdu $ body

getRid :: Packet -> Integer
getRid Packet{..} = rid . request . pdu $ body

getSuite :: Packet -> Suite
getSuite Packet{..} = suite . pdu $ body

setSuite :: Suite -> Packet -> Packet 
setSuite s Packet{..} = Packet header (body { pdu = (pdu body) { suite = s }})

setMaxSize :: MaxSize -> Packet -> Packet
setMaxSize m Packet{..} = case header of
                               HeaderV3{..} -> Packet (header { maXSize = m }) body
                               _ -> error "setMaxSize: bad version "

setMsgId :: ID -> Packet -> Packet
setMsgId i Packet{..} = case header of
                             HeaderV3{..} -> Packet (header { iD = i }) body
                             _ -> error "setMsgId: bad version "

setReportable :: Reportable -> Packet -> Packet
setReportable r Packet{..} = 
    case header of
       HeaderV3{..} -> let Flag _ a = flag
                      in Packet (header { flag = Flag r a }) body
       _ -> error "setReportable: bad version "

setPrivAuth :: PrivAuth -> Packet -> Packet
setPrivAuth a Packet{..} = 
   case header of
       HeaderV3{..} -> let Flag r _ = flag
                      in Packet (header { flag = Flag r a}) body
       _ -> error "setPrivAuth: bad version "

setRid :: RequestId -> Packet -> Packet
setRid r Packet{..} = 
    let p@PDU{..} = pdu body
    in Packet header (body { pdu = p { request = request { rid = r }}})

setRequest :: Request -> Packet -> Packet
setRequest r Packet{..} = 
    let p@PDU{..} = pdu body
    in Packet header (body { pdu = p { request = r }})

setCommunity :: Community -> Packet -> Packet
setCommunity c Packet{..} =
    case header of
         HeaderV2{..} -> Packet ( header { community = c } ) body
         _ -> error "setCommunity: bad version "

setPDU :: PDU -> Packet -> Packet
setPDU p Packet{..} = Packet header (body { pdu = p })

setUserName :: ByteString -> Packet -> Packet
setUserName u Packet{..} = 
    case header of
         HeaderV3{..} -> let s@SecurityParameter{..} = securityParameter
                        in Packet (header { securityParameter = s { userName = u }}) body
         _ -> error "setUserName: bad version "

setAuthenticationParameters :: ByteString -> Packet -> Packet
setAuthenticationParameters p Packet{..} = 
    case header of
         HeaderV3{..} -> let s@SecurityParameter{..} = securityParameter
                        in Packet (header { securityParameter = s { authenticationParameters = p }}) body
         _ -> error "setAuthenticationParameters: bad version "

setFlag :: Flag -> Packet -> Packet
setFlag f Packet{..} = 
    case header of
         HeaderV3{..} -> Packet (header { flag = f }) body
         _ -> error "setFlag: bad version " 

class Construct a where
    initial :: Version -> a

instance Construct Packet where
    initial Version3 = Packet (initial Version3) (initial Version3)
    initial v = Packet (initial v) (initial v)

instance Construct Header where
    initial Version3 = HeaderV3 Version3 (ID 0) (MaxSize 65007) (Flag False NoAuthNoPriv) UserBasedSecurityModel (initial Version3)
    initial v = HeaderV2 v (Community "")

instance Construct VersionedPDU where
    initial Version3 = ScopedPDU (ContextEngineID "") (ContextName "") (initial Version3)
    initial _ = SimplePDU (initial Version3)

instance Construct SecurityParameter where
    initial Version3 = SecurityParameter "" 0 0 "" "" ""
    initial _ = error "SecurityParameter: bad construct"

instance Construct PDU where
    initial _ = PDU (GetRequest 0 0 0) mempty
