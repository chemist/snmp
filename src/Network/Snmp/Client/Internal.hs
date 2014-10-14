module Network.Snmp.Client.Internal 
( oidFromBS
, makeSocket
, succCounter
, predCounter
, lastS
, isUpLevel
, uniqID
)
where

import Data.ByteString (ByteString)
import Network.Socket hiding (recv, socket, close)
import qualified Network.Socket as NS
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString.Char8 as C
import Control.Applicative ((<$>))
import Data.Maybe (catMaybes)
import Network.Protocol.Snmp (Coupla, Suite(..), OID)
import Network.Snmp.Client.Types (Port, Hostname)
import Data.IORef (IORef, atomicModifyIORef')
import Network.Info
import Data.Word (Word32)

oidFromBS :: ByteString -> [Integer]
oidFromBS xs = catMaybes $ map (\x -> fst <$> C.readInteger x) $ C.splitWith (== '.') xs

makeSocket :: Hostname -> Port -> IO Socket
makeSocket hostname port = do
    serverAddress <- head <$> getAddrInfo (Just defaultHints) (Just hostname) (Just port)
    sock <- NS.socket (addrFamily serverAddress) Datagram defaultProtocol
    connect sock (addrAddress serverAddress)
    return sock

succCounter :: IORef Integer -> IO Integer
succCounter ref = atomicModifyIORef' ref  (\x -> (succ x, succ x))

predCounter :: IORef Integer -> IO Integer
predCounter ref = atomicModifyIORef' ref  (\x -> (pred x, pred x))

lastS :: Suite -> Coupla
lastS (Suite xs) = last xs

isUpLevel :: OID -> OID -> Bool
isUpLevel new old = let baseLength = length old
                    in old /= take baseLength new 

uniqID :: IO Integer
uniqID = do
    nf <- getNetworkInterfaces
    let zeroMac = MAC 0 0 0 0 0 0
        zeroIp = IPv4 0
        zeroIpv6 = IPv6 0 0 0 0
        ipToW (IPv4 x) = x
    return $ case filter (\x -> ipv4 x /= zeroIp && mac x /= zeroMac ) nf of
         [] -> 1000000 -- i cant find ip address
         [x] -> toInteger $ ipToW (ipv4 x)
         x:_ -> toInteger $ ipToW (ipv4 x)



