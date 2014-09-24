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
, SnmpVersion(..)
, get
, bulkget
, getnext
, walk
, close
, Config(..)
, defConfig
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
import Network.Protocol.Simple
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
  , version :: SnmpVersion
  , timeout :: Int
  } deriving (Show, Eq)

sec :: Int -> Int
sec = (* 1000000)

defConfig :: Config
defConfig = Config "localhost" "161" (Community "public") Version2 (sec 5)

data Client = Client 
  { get :: OIDS -> IO SnmpData
  , bulkget :: OIDS -> IO SnmpData 
  , getnext :: OIDS -> IO SnmpData
  , walk :: OIDS -> IO SnmpData
  , close :: IO ()
  }

succRequestId :: IORef Integer -> IO Integer
succRequestId ref = atomicModifyIORef' ref  (\x -> (succ x, succ x))

data ClientException = TimeoutException 
                     | ServerException Integer
                     deriving (Typeable, Show, Eq)

instance Exception ClientException

client :: Config -> IO Client
client Config{..} = do
    socket <- trace "open socket" $ makeSocket hostname port 
    ref <- trace "init rid" $ newIORef 0
    let returnResult = do
            result <- race (threadDelay timeout) (decode <$> recv socket 1500)
            case result of
                 Right (SnmpPacket _ _ (PDU (GetResponse rid e ie) d)) -> do
                     when (e /= 0) $ throwIO $ ServerException e
                     return d
                 Left _ -> throwIO TimeoutException            

        get' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket version community (PDU (GetRequest rid 0 0) (SnmpData $ map (\x -> (x, Zero)) oids)))
            returnResult

        bulkget' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket version community (PDU (GetBulk rid 0 10) (SnmpData $ map (\x -> (x, Zero)) oids)))
            returnResult

        getnext' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket version community (PDU (GetNextRequest rid 0 0) (SnmpData $ map (\x -> (x, Zero)) oids)))
            returnResult

        walk' oids base accumulator 
            | oids == base = do
                first <- get' [oids]
                next <- getnext' [oids]
                case (first, next) of
                     (SnmpData [(_, NoSuchObject)], SnmpData [(nextOid, _)]) -> walk' nextOid base accumulator
                     (SnmpData [(_, NoSuchInstance)], SnmpData [(nextOid, _)]) -> walk' nextOid base accumulator
                     (SnmpData [(_, EndOfMibView)], _) -> return accumulator
                     (_, SnmpData [(nextOid, _)]) -> walk' nextOid base first
            | otherwise = do
                rid <- succRequestId ref
                sendAll socket $ encode (SnmpPacket version community (PDU (GetNextRequest rid 0 0) (SnmpData [(oids, Zero)])))
                result <- race (threadDelay timeout) (decode <$> recv socket 1500)
                case result of
                  Right (SnmpPacket _ _ (PDU (GetResponse rid e ie) d)) -> do
                    when (e /= 0) $ throwIO $ ServerException e
                    let SnmpData [(next, v)] = d
                    case (isUpLevel next base, v) of
                         (True, _) -> return accumulator
                         (_, NoSuchObject) -> walk' next base accumulator
                         (_, NoSuchInstance) -> walk' next base accumulator
                         (_, EndOfMibView) -> return accumulator
                         (_, _) -> walk' next base (accumulator <> d) 
                  Left _ -> throwIO TimeoutException            
    return $ Client 
        { get = get'
        , bulkget = bulkget'
        , getnext = getnext'
        , walk = \oids -> mconcat <$> mapM (\oi -> withSocketsDo $ walk' oi oi mempty) oids
        , close = trace "close socket" $ NS.close socket
        } 

isUpLevel :: OID -> OID -> Bool
isUpLevel new old = let baseLength = length old
                    in old /= take baseLength new 
