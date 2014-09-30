module Network.Snmp.Client.Internal 
( oidFromBS
, makeSocket
, succRequestId
, lastS
, isUpLevel
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

oidFromBS :: ByteString -> [Integer]
oidFromBS xs = catMaybes $ map (\x -> fst <$> C.readInteger x) $ C.splitWith (== '.') xs

makeSocket :: Hostname -> Port -> IO Socket
makeSocket hostname port = do
    serverAddress <- head <$> getAddrInfo (Just defaultHints) (Just hostname) (Just port)
    sock <- NS.socket (addrFamily serverAddress) Datagram defaultProtocol
    connect sock (addrAddress serverAddress)
    return sock

succRequestId :: IORef Integer -> IO Integer
succRequestId ref = atomicModifyIORef' ref  (\x -> (succ x, succ x))

lastS :: Suite -> Coupla
lastS (Suite xs) = last xs

isUpLevel :: OID -> OID -> Bool
isUpLevel new old = let baseLength = length old
                    in old /= take baseLength new 
