{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Network.Snmp.Client 
-- * types
( Client
, Port
, Hostname
, Login
, Password
, Version(..)
, Community(..)
, Config(..)
, Coupla(..)
, Suite(..)
, Value(String, Integer, IpAddress, Counter32, Gaude32, TimeTicks, Opaque, Counter64, ZeroDotZero, Zero)
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
-- * usefull functions
, oidFromBS
, defConfig
)
where

import Network.Protocol.Snmp
import Network.Snmp.Client.Types
import Network.Snmp.Client.Internal
import Network.Snmp.Client.Version2
import Network.Snmp.Client.Version3

client :: Config -> IO Client
client ConfigV2{..} = clientV2 hostname port timeout community
client ConfigV3{..} = clientV3 hostname port timeout login password
