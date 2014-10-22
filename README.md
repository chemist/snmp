snmp
====

[![Build Status](https://travis-ci.org/chemist/snmp.svg?branch=master)](https://travis-ci.org/chemist/snmp)
[![Gitter chat](https://badges.gitter.im/chemist/snmp.png)](https://gitter.im/chemist/snmp)

This is library for work with SNMPv2, SNMPv3.

It can be usefull if you need write agent or server.

Usage example:

```haskell
import Data.ByteString (ByteString)
import Control.Exception (bracket, try)

import Network.Snmp.Client
import Network.Protocol.Snmp

-- For SNMPv2
conf2 :: Config
conf2 = (initial Version2) { hostname = "salt" 
                           , community = Community "helloall"
                           } 

-- For SNMPv3
conf3 :: Config
conf3 = (initial Version3) { hostname = "salt" 
                           , sequrityName = "aes"
                           , authPass = "helloallhello"
                           , privPass = "helloallhello"
                           , authType = SHA
                           , privType = AES
                           , sequrityLevel = AuthPriv
                           } 
-- do io 
client3 :: IO ()
client3 = bracket (client conf3)
                  close
                  requests

client2 :: IO ()
client2 = bracket (client conf2)
                  close
                  requests

-- Describe oids which you need
root, eth0, tabl, ipAddr, zeroDotZero :: [Integer]
root = [1,3,6,1,2,1,2,2,1,2]
eth0 = [1,3,6,1,2,1,2,2,1,2,1]
tabl = [31,1,1,1,1]
ipAddr = [1,3,6,1,2,1,4,22,1,3,3,192,168,3,1]
zeroDotZero = [1,3,6,1,2,1,2,2,1,22,20]

oi, sysUptime, memory, sysContact, bad, testOid :: ByteString
oi = ".1.3.6.1.2.1.1.9.1.2.1"
sysUptime = "1.3.6.1.2.1.25.1.1.0"
memory = "1.3.6.1.2.1.25.2"
sysContact = "1.3.6.1.2.1.1.4.0"
bad = "1.4.6.1.2.1.1.4"
testOid = "1.3.6.1.2.1.25.1.1.0"

-- Describe requests
requests :: Client -> IO ()
requests snmp = do
    print "get request"
    putStr . show =<< get snmp [oidFromBS testOid]
    putStr . show =<< get snmp [oidFromBS testOid]
    putStr . show =<< get snmp [oidFromBS sysUptime, oidFromBS oi, zeroDotZero]
    print "bulkget request"
    putStr . show =<< bulkget snmp [oidFromBS sysUptime]
    print "getnext request"
    putStr . show =<< getnext snmp [oidFromBS sysUptime]
    print "walk memory"
    putStr . show =<< walk snmp [oidFromBS memory]
    print "bulkwalk memory"
    putStr . show =<< bulkwalk snmp [oidFromBS memory]
    print "get sysContact"
    putStr . show =<< get snmp [oidFromBS sysContact]
    print "set sysContact"
    putStr . show =<< (try $ set snmp (Suite [Coupla (oidFromBS sysContact) (String "hello all")]) :: IO (Either ClientException Suite))
    print "get sysContact"
    putStr . show =<< get snmp [oidFromBS sysContact]
```
