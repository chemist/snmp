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
, ScopedPDU(..)
-- * aliases
, V2Packet
, V3Packet
, Hostname
, Port
-- * client types
, Config(..) 
, Client(..)
, sec
, OIDS
) 
where

import Network.Protocol.Snmp.Types
import Network.Protocol.Snmp.Version2
import Network.Protocol.Snmp.Version3 

type V2Packet = SnmpPacket (Header Community) PDU
type V3Packet = SnmpPacket (Header Context) ScopedPDU

type OIDS = [OID]

type Hostname = String
type Port = String
type Login = String
type Password = String

data Config = ConfigV2
  { hostname :: Hostname
  , port :: Port
  , timeout :: Int
  , community :: Community
  }         | ConfigV3
  { hostname :: Hostname
  , port :: Port
  , timeout :: Int
  , login :: Login
  , password :: Password
  }
  deriving (Show, Eq)

sec :: Int -> Int
sec = (* 1000000)

data Client = Client 
  { get :: OIDS -> IO Suite
  , bulkget :: OIDS -> IO Suite 
  , getnext :: OIDS -> IO Suite
  , walk :: OIDS -> IO Suite
  , bulkwalk :: OIDS -> IO Suite
  , set :: Suite -> IO Suite
  , close :: IO ()
  }



