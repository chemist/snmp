snmp
====

[![Build Status](https://travis-ci.org/chemist/snmp.svg?branch=master)](https://travis-ci.org/chemist/snmp)
[![Gitter chat](https://badges.gitter.im/chemist/snmp.png)](https://gitter.im/chemist/snmp)

SNMP protocol implementation. Supports v1, v2c and v3 versions.

Usage example:
```haskell
import Network.Protocol.Snmp
import Control.Applicative
import Network.Socket.ByteString (recv, sendAll)
import Network.Socket hiding (recv, sendAll)

-- create new empty packet
v2 :: Packet
v2 = initial Version2

community = Community "hello"

oi = Coupla [1,3,6,1,2,1,1,4,0] Zero

-- set community, oid
packet :: Community -> Coupla -> Packet
packet community oi =
  setCommunityP community . setSuite (Suite [oi]) $ v2

-- here must be code for create udp socket
makeSocket :: Hostname -> Port -> IO Socket
makeSocket = undefined

main :: IO ()
main = do
   socket <- makeSocket "localhost" "161"
   sendAll socket $ encode $ setRequest (GetRequest 1 0 0) packet
   result <- decode <$> recv socket 1500 :: IO Packet
   print $ getSuite result
```
