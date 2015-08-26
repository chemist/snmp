{-# LANGUAGE OverloadedStrings #-}
module Network.Snmp.Example (
-- * Usage
-- ** Imports
-- $imports

-- ** Create config
-- $config
 
-- ** Describe oids
-- $oids

-- ** Describe requests
-- $request

-- ** Do IO
-- $send
) where

import Data.ByteString (ByteString)
import Control.Exception (bracket, try)

import Network.Snmp.Client
import Network.Protocol.Snmp

{- $imports
> -- imports here
> import Data.ByteString (ByteString)
> import Control.Exception (bracket, try)
> 
> import Network.Snmp.Client
> import Network.Protocol.Snmp
-}

{- $config
> -- First you must create config
> -- For SNMPv1
> conf1 :: Config
> conf1 = (initial Version1) { hostname = "salt" 
>                            , community = Community "helloall"
>                            } 
> -- For SNMPv2
> conf2 :: Config
> conf2 = (initial Version2) { hostname = "salt" 
>                            , community = Community "helloall"
>                            } 
> 
> -- For SNMPv3
> conf3 :: Config
> conf3 = (initial Version3) { hostname = "salt" 
>                            , securityName = "aes"
>                            , authPass = "helloallhello"
>                            , privPass = "helloallhello"
>                            , authType = SHA
>                            , privType = AES
>                            , securityLevel = AuthPriv
>                            } 
> 
-}
conf1 :: Config
conf1 = (initial Version1) { hostname = "salt" 
                           , community = Community "helloall"
                           } 
conf2 :: Config
conf2 = (initial Version2) { hostname = "salt" 
                           , community = Community "helloall"
                           } 

-- For SNMPv3
conf3 :: Config
conf3 = (initial Version3) { hostname = "salt" 
                           , securityName = "aes"
                           , authPass = "helloallhello"
                           , privPass = "helloallhello"
                           , authType = SHA
                           , privType = AES
                           , securityLevel = AuthPriv
                           } 

{- $send
> -- do io 
> client3 :: IO ()
> client3 = bracket (client conf3)
>                   close
>                   requests
> 
> client2 :: IO ()
> client2 = bracket (client conf2)
>                   close
>                   requests
>
> client1 :: IO ()
> client1 = bracket (client conf1)
>                   close
>                   requests
> 
-}
client3 :: IO ()
client3 = bracket (client conf3)
                  close
                  requests

client2 :: IO ()
client2 = bracket (client conf2)
                  close
                  requests

client1 :: IO ()
client1 = bracket (client conf1)
                  close
                  requests

{- $oids
> -- Describe oids which you need
> root, eth0, tabl, ipAddr, zeroDotZero :: [Integer]
> root = [1,3,6,1,2,1,2,2,1,2]
> eth0 = [1,3,6,1,2,1,2,2,1,2,1]
> tabl = [31,1,1,1,1]
> ipAddr = [1,3,6,1,2,1,4,22,1,3,3,192,168,3,1]
> zeroDotZero = [1,3,6,1,2,1,2,2,1,22,20]
> 
> oi, sysUptime, memory, sysContact, bad, testOid :: ByteString
> oi = ".1.3.6.1.2.1.1.9.1.2.1"
> sysUptime = "1.3.6.1.2.1.25.1.1.0"
> memory = "1.3.6.1.2.1.25.2"
> sysContact = "1.3.6.1.2.1.1.4.0"
> bad = "1.4.6.1.2.1.1.4"
> testOid = "1.3.6.1.2.1.25.1.1.0"
-}
root, eth0, tabl, ipAddr, zeroDotZero :: [Integer]
root = [1,3,6,1,2,1,2,2,1,2]
eth0 = [1,3,6,1,2,1,2,2,1,2,1]
tabl = [31,1,1,1,1]
ipAddr = [1,3,6,1,2,1,4,22,1,3,3,192,168,3,1]
zeroDotZero = [1,3,6,1,2,1,2,2,1,22,20]

oi, sysUptime, memory, sysContact, bad, testOid, inet :: ByteString
oi = ".1.3.6.1.2.1.1.9.1.2.1"
sysUptime = "1.3.6.1.2.1.25.1.1.0"
memory = "1.3.6.1.2.1.25.2"
sysContact = "1.3.6.1.2.1.1.4.0"
bad = "1.4.6.1.2.1.1.4"
testOid = "1.3.6.1.2.1.25.1.1.0"
inet = ".1.3.6.1"

{- $request
> -- Describe requests
> requests :: Client -> IO ()
> requests snmp = do
>     print "get request"
>     putStr . show =<< get snmp [oidFromBS testOid]
>     putStr . show =<< get snmp [oidFromBS testOid]
>     putStr . show =<< get snmp [oidFromBS sysUptime, oidFromBS oi, zeroDotZero]
>     print "bulkget request"
>     putStr . show =<< bulkget snmp [oidFromBS sysUptime]
>     print "getnext request"
>     putStr . show =<< getnext snmp [oidFromBS sysUptime]
>     print "walk memory"
>     putStr . show =<< walk snmp [oidFromBS memory]
>     print "bulkwalk memory"
>     putStr . show =<< bulkwalk snmp [oidFromBS memory]
>     print "get sysContact"
>     putStr . show =<< get snmp [oidFromBS sysContact]
>     print "set sysContact"
>     putStr . show =<< (try $ set snmp (Suite [Coupla (oidFromBS sysContact) (String "hello all")]) :: IO (Either ClientException Suite))
>     print "get sysContact"
>     putStr . show =<< get snmp [oidFromBS sysContact]
-}
requests :: Client -> IO ()
requests snmp = do
    print "get request"
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

