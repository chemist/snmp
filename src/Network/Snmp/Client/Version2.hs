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

v2 :: Packet
v2 = newPacket Version2

returnResult2 :: NS.Socket -> Int -> IO Suite
returnResult2 socket timeout = do
    result <- race (threadDelay timeout) (decode <$> recv socket 1500 :: IO Packet)
    case result of
         Right packet -> do
             when (getErrorStatus packet /= 0) $ throwIO $ ServerException $ getErrorStatus packet
             return $ getSuite packet
         Left _ -> throwIO TimeoutException            

setRCS :: Community -> OIDS -> Packet -> Packet
setRCS c o = setCommunity c . setSuite (Suite $ map (\x -> Coupla x Zero) o)

clientV2 :: Hostname -> Port -> Int -> Community -> IO Client
clientV2 hostname port timeout community = do
    socket <- trace "open socket" $ makeSocket hostname port 
    ref <- trace "init rid" $ newIORef 0
    let 
        req oids = setRCS community oids v2
        get' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode $ setRequest (GetRequest rid 0 0) (req oids) 
            returnResult2 socket timeout

        bulkget' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode $ setRequest (GetBulk rid 0 10) (req oids)
            returnResult2 socket timeout

        getnext' oids = withSocketsDo $ do
            rid <- succRequestId ref
            sendAll socket $ encode $ setRequest (GetNextRequest rid 0 0) (req oids)
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
            sendAll socket $ encode $ setRequest (SetRequest rid 0 0) . setCommunity community . setSuite oids $ v2
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

