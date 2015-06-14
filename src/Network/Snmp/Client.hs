{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE RecordWildCards #-}
module Network.Snmp.Client (
-- * types
  Client
, Port
, Hostname
, Login
, Password
, Version(..)
, Community(..)
, Config(..)
, Coupla(..)
, Suite(..)
, PrivAuth(..)
, AuthType(..)
, Value(String, Integer, IpAddress, Counter32, Gauge32, TimeTicks, Opaque, Counter64, ZeroDotZero, Zero, OI)
-- * client 
, client
-- ** client methods
, get
, bulkget
, getnext
, walk
, bulkwalk
, set
, close
-- * useful functions
, oidFromBS
)
where

import Network.Protocol.Snmp
import Network.Snmp.Client.Types
import Network.Snmp.Client.Internal
import Network.Snmp.Client.Version2
import Network.Snmp.Client.Version3

client :: Config -> IO Client
client conf@ConfigV2{..} = clientV2 hostname 
                                    port 
                                    timeout 
                                    community
client conf@ConfigV3{..}  = clientV3 hostname       
                                     port           
                                     timeout        
                                     sequrityName   
                                     authPass       
                                     privPass       
                                     sequrityLevel  
                                     authType       
                                     privType      
