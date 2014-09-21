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

root :: [Integer]
root = [1,3,6,1,2,1,2,2,1,2]

eth0 = [1,3,6,1,2,1,2,2,1,2, 1]

snmpServer :: HostName
snmpServer = "limbo"

community = Community "helloall"
version = Version2


getRequest :: [Integer] -> IO ()
getRequest oid = withSocketsDo $ do
    serverAddress <- head <$> getAddrInfo (Just defaultHints) (Just snmpServer) (Just "161")
    sock <- socket (addrFamily serverAddress) Datagram defaultProtocol
    connect sock (addrAddress serverAddress)
    sendAll sock $ get agent version community 1 oid
    print =<< (result agent <$> recv sock 1500) -- cant be bigger without getting fragmented (see MTU)
    sendAll sock $ bulk agent version community 2 10 oid
    print =<< (result agent <$> recv sock 1500) -- cant be bigger without getting fragmented (see MTU)

main = mapM_ (\x -> (getRequest $ root ++ [x])) [1 .. 9]
