{-# LANGUAGE OverloadedStrings #-}
module Main where

import Data.ByteString.Lazy (toStrict, fromStrict)
import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)
import Control.Applicative
import Data.Maybe
import Debug.Trace
import Prelude hiding (writeFile, readFile)
import Network.Protocol.Snmp

getEth0 :: [Integer]
getEth0 = [1,3,6]

eth0 = [1,3,6,1,2,1,2,2,1,6]

snmpServer :: HostName
snmpServer = "limbo"

test oid = Snmp Version2 "helloall" (GetRequest oid) 1

doRequest :: Snmp -> IO Snmp
doRequest snmp = withSocketsDo $ do
    serverAddress <- head <$> getAddrInfo (Just defaultHints) (Just snmpServer) (Just "161")
    sock <- socket (addrFamily serverAddress) Datagram defaultProtocol
    connect sock (addrAddress serverAddress)
    sendAll sock $ encode snmp
    decode <$> recv sock 1500 -- cant be bigger without getting fragmented (see MTU)

main = mapM_ (\x -> print =<< (doRequest $ test $ eth0 ++ [x])) [1 .. 9]
