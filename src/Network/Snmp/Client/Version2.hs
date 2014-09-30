module Network.Snmp.Client.Version2
( clientV2
)
where

import Network.Socket hiding (recv, socket, close)
import qualified Network.Socket as NS
import Network.Socket.ByteString (recv, sendAll)
import Control.Applicative ((<$>))
import Control.Concurrent.Async
import Data.IORef (newIORef)
import Control.Concurrent (threadDelay)
import Control.Exception
import Control.Monad (when)
import Data.Monoid ((<>), mconcat, mempty)
import Debug.Trace

import Network.Protocol.Snmp 
import Network.Snmp.Client.Internal
import Network.Snmp.Client.Types

returnResult2 :: NS.Socket -> Int -> IO Suite
returnResult2 socket timeout = do
    result <- race (threadDelay timeout) (decode <$> recv socket 1500 :: IO V2Packet)
    case result of
         Right (SnmpPacket _ (PDU (GetResponse rid e ie) d)) -> do
             when (e /= 0) $ throwIO $ ServerException e
             return d
         Left _ -> throwIO TimeoutException            

clientV2 :: Hostname -> Port -> Int -> Community -> IO Client
clientV2 hostname port timeout community = do
    socket <- trace "open socket" $ makeSocket hostname port 
    ref <- trace "init rid" $ newIORef 0
    let 
        get' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket (Header Version2 community) (PDU (GetRequest rid 0 0) (Suite $ map (\x -> Coupla x Zero) oids)))
            returnResult2 socket timeout

        bulkget' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket (Header Version2 community) (PDU (GetBulk rid 0 10) (Suite $ map (\x -> Coupla x Zero) oids)))
            returnResult2 socket timeout

        getnext' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode (SnmpPacket (Header Version2 community) (PDU (GetNextRequest rid 0 0) (Suite $ map (\x -> Coupla x Zero) oids)))
            returnResult2 socket timeout

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
            sendAll socket $ encode (SnmpPacket (Header Version2 community) (PDU (SetRequest rid 0 0) oids))
            returnResult2 socket timeout

    return $ Client 
        { get = get'
        , bulkget = bulkget'
        , getnext = getnext'
        , walk = \oids -> mconcat <$> mapM (\oi -> withSocketsDo $ walk' oi oi mempty) oids
        , bulkwalk = \oids -> mconcat <$> mapM (\oi -> withSocketsDo $ bulkwalk' oi oi mempty) oids
        , set = set' 
        , close = trace "close socket" $ NS.close socket
        } 

