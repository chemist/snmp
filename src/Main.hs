{-# LANGUAGE OverloadedStrings #-}
module Main where

import Data.ByteString (ByteString)
import Network.Snmp.Client
import Control.Exception (bracket)
import Debug.Trace

root :: [Integer]
root = [1,3,6,1,2,1,2,2,1,2]

eth0 = [1,3,6,1,2,1,2,2,1,2, 1]

tabl = [31,1,1,1,1]

sysUptime = "1.3.6.1.2.1.25.1.1.0"

memory = "1.3.6.1.2.1.25.2"

ipAddr = [1,3,6,1,2,1,4,22,1,3,3,192,168,3,1]

zeroDotZero = [1,3,6,1,2,1,2,2,1,22,20]

sysContact = "1.3.6.1.2.1.1.4.0"
bad = "1.4.6.1.2.1.1.4"

oi :: ByteString
oi = ".1.3.6.1.2.1.1.9.1.2.1"

main = client3

conf2 :: Config
conf2 = (defConfig Version2) { hostname = "salt" 
                             , community = Community "helloallrw"
                             } 
conf3 :: Config
conf3 = (defConfig Version3) { hostname = "salt" 
                             , login = "chemist"
                             , password = "helloallrw"
                             } 

client3 = bracket (client conf3)
                  close
                  requests


client2 = bracket (client conf2)
                  close
                  requests

requests :: Client -> IO ()
requests snmp = do
    print "get request"
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
    putStr . show =<< set snmp (Suite [Coupla (oidFromBS sysContact) (String "hello all")])
    print "get sysContact"
    putStr . show =<< get snmp [oidFromBS sysContact]

