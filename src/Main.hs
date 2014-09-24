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

oi :: ByteString
oi = ".1.3.6.1.2.1.1.9.1.2.1"

conf = defConfig { hostname = "salt"
                 , community = Community "helloall"
                 , port = "161"
                 }

main = bracket (client conf)
               close
               requests
       where
         requests :: Client -> IO ()
         requests snmp = do
             print "only sysUptime"
             putStr . show =<< walk snmp [oidFromBS sysUptime]
             print "memory"
             putStr . show =<< walk snmp [oidFromBS memory]
--             print "get request"
--             putStr . show =<< get snmp [sysUptime, oidFromBS oi, zeroDotZero, sysUptime]
--             print "bulkget request"
--             putStr . show =<< bulkget snmp [sysUptime]
--             print "getnext request"
--             putStr . show =<< getnext snmp [sysUptime]

