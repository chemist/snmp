{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Network.Snmp.Client 
( Client
, client
, Hostname
, Port
, oidFromBS
, Community(..)
, Version(..)
, get
, bulkget
, getnext
, walk
, bulkwalk
, set
, close
, Config(..)
, defConfig
, Coupla(..)
, Suite(..)
, Value(String, Integer, IpAddress, Counter32, Gaude32, TimeTicks, Opaque, Counter64, ZeroDotZero, Zero)
)
where

import Data.ByteString (ByteString)
import Network.Socket hiding (recv, socket, close)
import qualified Network.Socket as NS
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Control.Applicative
import Data.Maybe
import Network.Protocol.Snmp
import Control.Concurrent.Async
import Data.IORef
import Control.Concurrent (threadDelay)
import Control.Exception
import Data.Typeable
import Control.Monad (when)
import Data.Monoid
import Debug.Trace

oidFromBS :: ByteString -> [Integer]
oidFromBS xs = catMaybes $ map (\x -> fst <$> C.readInteger x) $ C.splitWith (== '.') xs

type Hostname = String
type Port = String

makeSocket :: Hostname -> Port -> IO Socket
makeSocket hostname port = do
    serverAddress <- head <$> getAddrInfo (Just defaultHints) (Just hostname) (Just port)
    sock <- NS.socket (addrFamily serverAddress) Datagram defaultProtocol
    connect sock (addrAddress serverAddress)
    return sock

type OIDS = [OID]

data Config = Config 
  { hostname :: Hostname
  , port :: Port
  , community :: Community
  , version :: Version
  , timeout :: Int
  } deriving (Show, Eq)

sec :: Int -> Int
sec = (* 1000000)

defConfig :: Config
defConfig = Config "localhost" "161" (Community "public") Version2 (sec 5)

data Client = Client 
  { get :: OIDS -> IO Suite
  , bulkget :: OIDS -> IO Suite 
  , getnext :: OIDS -> IO Suite
  , walk :: OIDS -> IO Suite
  , bulkwalk :: OIDS -> IO Suite
  , set :: Suite -> IO Suite
  , close :: IO ()
  }

succRequestId :: IORef Integer -> IO Integer
succRequestId ref = atomicModifyIORef' ref  (\x -> (succ x, succ x))

client :: Config -> IO Client
client Config{..} = do
    socket <- trace "open socket" $ makeSocket hostname port 
    ref <- trace "init rid" $ newIORef 0
    let returnResult = do
            result <- race (threadDelay timeout) (decode <$> recv socket 1500)
            case result of
                 Right (SnmpPacket (Header Version2 (Community _)) (PDU (GetResponse rid e ie) d)) -> do
                     when (e /= 0) $ throwIO $ ServerException e
                     return d
                 Left _ -> throwIO TimeoutException            

        get' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket (Header version community) (PDU (GetRequest rid 0 0) (Suite $ map (\x -> Coupla x Zero) oids)))
            returnResult

        bulkget' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket (Header version community) (PDU (GetBulk rid 0 10) (Suite $ map (\x -> Coupla x Zero) oids)))
            returnResult

        getnext' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket (Header version community) (PDU (GetNextRequest rid 0 0) (Suite $ map (\x -> Coupla x Zero) oids)))
            returnResult

        walk' oids base accumulator 
            | oids == base = do
                first <- get' [oids]
                next <- getnext' [oids]
                case (first, next) of
                     (Suite [Coupla _ NoSuchObject], Suite [Coupla nextOid _]) -> walk' nextOid base next
                     (Suite [Coupla _ NoSuchInstance], Suite [Coupla nextOid _]) -> walk' nextOid base next
                     (Suite [Coupla _ EndOfMibView], _) -> return accumulator
                     (_, Suite [Coupla nextOid _]) -> walk' nextOid base first
            | otherwise = do
                nextData <- getnext' [oids]
                let Suite [Coupla next v] = nextData
                case (isUpLevel next base, v) of
                     (True, _) -> return accumulator
                     (_, NoSuchObject) -> walk' next base accumulator
                     (_, NoSuchInstance) -> walk' next base accumulator
                     (_, EndOfMibView) -> return accumulator
                     (_, _) -> walk' next base (accumulator <> nextData) 
        bulkwalk' oids base accumulator = do
               first <- bulkget' [oids]
               let Coupla next snmpData = lastS first
                   filtered (Suite xs) = Suite $ filter (\(Coupla x _) -> not $ isUpLevel x base) xs
               case (isUpLevel next base , snmpData) of
                    (_, EndOfMibView) -> return $ accumulator <> filtered first
                    (False, _) -> bulkwalk' next base (accumulator <> first)
                    (True, _) -> return $ accumulator <> filtered first
        set' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket (Header version community) (PDU (SetRequest rid 0 0) oids))
            returnResult

    return $ Client 
        { get = get'
        , bulkget = bulkget'
        , getnext = getnext'
        , walk = \oids -> mconcat <$> mapM (\oi -> withSocketsDo $ walk' oi oi mempty) oids
        , bulkwalk = \oids -> mconcat <$> mapM (\oi -> withSocketsDo $ bulkwalk' oi oi mempty) oids
        , set = set' 
        , close = trace "close socket" $ NS.close socket
        } 

lastS :: Suite -> Coupla
lastS (Suite xs) = last xs

isUpLevel :: OID -> OID -> Bool
isUpLevel new old = let baseLength = length old
                    in old /= take baseLength new 
