{-# LANGUAGE OverloadedStrings #-}
module Network.Protocol.Snmp 
-- * Types
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
-- * Second version
, Community(..)
-- * Third version
, Context(..)
, ContextEngineID(..)
, ContextName(..)
, ScopedPDU(..)
, MsgID(..)
, MsgFlag(..)
, MsgMaxSize(..)
, MsgSecurityModel(..)
, MsgSecurityParameter(..)
, Reportable(..)
, PrivAuth(..)
-- * aliases
, V2Packet
, V3Packet
, OIDS
) 
where

import Network.Protocol.Snmp.Types
import Network.Protocol.Snmp.Version2
import Network.Protocol.Snmp.Version3 

type V2Packet = SnmpPacket (Header Community) PDU
type V3Packet = SnmpPacket (Header Context) ScopedPDU

type OIDS = [OID]


