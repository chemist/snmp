{-# LANGUAGE OverloadedStrings #-}
module Main where

import Data.ByteString (ByteString)
import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Control.Applicative
import Data.Maybe
import Prelude hiding (writeFile, readFile)
import Network.Protocol.Snmp

import Debug.Trace

root :: [Integer]
root = [1,3,6,1,2,1,2,2,1,2]

eth0 = [1,3,6,1,2,1,2,2,1,2, 1]

snmpServer :: HostName
snmpServer = "salt"

tabl = [31,1,1,1,1]

sysUptime = [1,3,6,1,2,1,25,1,1,0]

ipAddr = [1,3,6,1,2,1,4,22,1,3,3,192,168,3,1]

zeroDotZero = [1,3,6,1,2,1,2,2,1,22,20]

community = Community "helloall"
version = Version2

oi :: ByteString
oi = ".1.3.6.1.2.1.1.9.1.2.1"

toOID :: ByteString -> [Integer]
toOID xs = catMaybes $ map (\x -> fst <$> C.readInteger x) $ C.splitWith (== '.') xs

getRequest :: [Integer] -> IO ()
getRequest oid = withSocketsDo $ do
    serverAddress <- head <$> getAddrInfo (Just defaultHints) (Just snmpServer) (Just "161")
    sock <- socket (addrFamily serverAddress) Datagram defaultProtocol
    connect sock (addrAddress serverAddress)
    sendAll sock $ get agent version community 1 oid
    print =<< (result agent <$> recv sock 1500) -- cant be bigger without getting fragmented (see MTU)
    sendAll sock $ bulk agent version community 1 10 oid
    print =<< (result agent <$> recv sock 1500) -- cant be bigger without getting fragmented (see MTU)

main = mapM_ (\x -> (getRequest $ root ++ [x])) [1 .. 9]

macAddr :: ByteString
macAddr = "\224\203NQ\198C"
               
