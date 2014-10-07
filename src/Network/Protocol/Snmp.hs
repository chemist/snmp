{-# LANGUAGE OverloadedStrings #-}
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
, ID(..)
, Flag
, MaxSize(..)
, SecurityModel
, SecurityParameter
, Reportable
, PrivAuth(..)
-- ^ setters
, setID
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
, newPacket
) 
where

import Network.Protocol.Snmp.Types hiding (setID, setMaxSize, setCommunity)
import qualified Network.Protocol.Snmp.Types as T
import Data.ByteString (ByteString)
import Data.Monoid (mempty)

type OIDS = [OID]

setID :: ID -> Packet -> Packet 
setID x p = 
  let header = getHeader p :: Header V3
      newHeader = T.setID x header
  in setHeader newHeader p

setMaxSize :: MaxSize -> Packet -> Packet 
setMaxSize x p = 
  let header = getHeader p :: Header V3
      newHeader = T.setMaxSize x header
  in setHeader newHeader p 

setCommunity :: Community -> Packet -> Packet 
setCommunity x p = 
  let header = getHeader p :: Header V2
      newHeader = T.setCommunity x header
  in setHeader newHeader p

getEngineId :: Packet -> ContextEngineID
getEngineId p = getContextEngineID $ (getPDU p :: PDU V3)

setReportable :: Reportable -> Packet -> Packet
setReportable r p = 
  let header = getHeader p :: Header V3
      Flag _ a = getFlag header
      newHeader = setFlag (Flag r a) header
  in setHeader newHeader p

setPrivAuth :: PrivAuth -> Packet -> Packet
setPrivAuth x p = 
  let header = getHeader p :: Header V3
      Flag r _ = getFlag header
      newHeader = setFlag (Flag r x) header
  in setHeader newHeader p

setUserName :: ByteString -> Packet -> Packet 
setUserName x p = 
  let header = getHeader p :: Header V3
      sp = getSecurityParameter header
      newHeader = setSecurityParameter (sp { userName = x }) header
  in setHeader newHeader p

setAuthenticationParameters :: ByteString -> Packet -> Packet 
setAuthenticationParameters x p = 
  let header = getHeader p :: Header V3
      sp = getSecurityParameter header
      newHeader = setSecurityParameter (sp { authenticationParameters = x }) header
  in setHeader newHeader p


