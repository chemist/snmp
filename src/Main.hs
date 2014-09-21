{-# LANGUAGE OverloadedStrings #-}
module Main where

import Data.ByteString (ByteString)
import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)
import Control.Applicative
import Data.Maybe
import Data.ASN1.Types
import Debug.Trace
import Prelude hiding (writeFile, readFile)
import Network.Protocol.Snmp

getEth0 :: [Integer]
getEth0 = [1,3,6]

eth0 = [1,3,6,1,2,1,2,2,1,6]

snmpServer :: HostName
snmpServer = "limbo"

community = Community "helloall"
version = Version2


getRequest :: [Integer] -> IO (SnmpVersion, Community, Request, SnmpData)
getRequest oid = withSocketsDo $ do
    serverAddress <- head <$> getAddrInfo (Just defaultHints) (Just snmpServer) (Just "161")
    sock <- socket (addrFamily serverAddress) Datagram defaultProtocol
    connect sock (addrAddress serverAddress)
    sendAll sock $ pack snmp version community (GetRequest 1 0 0) (SnmpData [(oid, Null)])
    unpack snmp <$> recv sock 1500 -- cant be bigger without getting fragmented (see MTU)

main = mapM_ (\x -> print =<< (getRequest $ eth0 ++ [x])) [1 .. 9]
