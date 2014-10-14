{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.Snmp.Client.Version3 
-- ( clientV3
-- , msg
-- )
where

import Data.ByteString (ByteString)
import Network.Socket hiding (recv, socket, close)
import qualified Network.Socket as NS
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as C
import Control.Applicative ((<$>))
import Control.Concurrent.Async
import Data.IORef (newIORef, IORef, readIORef, atomicWriteIORef)
import Control.Concurrent (threadDelay)
import Control.Monad (when)
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types hiding (Context) 
import qualified Data.Binary as Bin (encode)
import Data.Monoid ((<>), mempty, mconcat)
import Data.Bits (xor)
import Data.Word (Word8)
import Control.Exception 
import Debug.Trace

import Network.Protocol.Snmp
import Network.Snmp.Client.Types
import Network.Snmp.Client.Internal 

v3 :: Packet 
v3 = initial Version3 

data ST = ST
  { authCache' :: IORef (Maybe ByteString)
  , privCache' :: IORef (Maybe ByteString)
  , engine' :: IORef (Maybe (ByteString, Integer, Integer))
  , ref' :: IORef Integer
  , saltInt' :: IORef Integer
  , securityLevel' :: PrivAuth
  , authType' :: AuthType
  , privType' :: PrivType
  , timeout' :: Int
  , socket' :: Socket
  , login' :: Login
  , authPass' :: Password
  , privPass' :: Password
  } 

clientV3 :: Hostname -> Port -> Int -> Login -> Password -> Password -> PrivAuth -> AuthType -> PrivType -> IO Client
clientV3 hostname port timeout sequrityName authPass privPass securityLevel authType privType = do
    socket <- makeSocket hostname port 
    uniqInteger <- uniqID
    ref <- newIORef uniqInteger
    saltInt <- newIORef 1
    authCache <- newIORef Nothing
    privCache <- newIORef Nothing
    engine <- newIORef Nothing
    let st = ST authCache privCache engine ref saltInt securityLevel authType privType timeout socket sequrityName authPass privPass
    return $ Client 
      { get = get' st
      , bulkget = bulkget' st
      , getnext = getnext' st
      , walk = \oids -> mconcat <$> mapM (\oi -> walk' st oi oi mempty) oids
      , bulkwalk = \oids -> mconcat <$> mapM (\oi -> bulkwalk' st oi oi mempty) oids
      , set = set' st
      , close = NS.close socket
      }


init' :: ST -> IO (ByteString, Integer, Integer)
init' st = withSocketsDo $ do
    rid <- predCounter (ref' st)
    sendAll (socket' st) $ encode $ packet rid
    resp <- decode <$> recv (socket' st) 1500 :: IO Packet
    atomicWriteIORef (engine' st) $ Just (getEngineIdP resp, getEngineBootsP resp, getEngineTimeP resp) 
    return (getEngineIdP resp, getEngineBootsP resp, getEngineTimeP resp)
    where
      packet x = ( setIDP (ID x)
                 . setMaxSizeP (MaxSize 65007)
                 . setReportableP False
                 . setPrivAuthP NoAuthNoPriv
                 . setRid x
                 ) v3


get' :: ST -> OIDS -> IO Suite
get' st oids = withSocketsDo $ do
    full <- packet st (toEmptySuite oids) GetRequest
    sendPacket st full
    packet <-  decryptPacketWithCache st =<< returnResult st
    checkError packet
    return $ getSuite packet

bulkget' :: ST -> OIDS -> IO Suite
bulkget' st oids = withSocketsDo $ do
    full <- packet st (toEmptySuite oids) GetBulk
    sendPacket st full
    packet <-  decryptPacketWithCache st =<< returnResult st
    checkError packet
    return $ getSuite packet

getnext' :: ST -> OIDS -> IO Suite
getnext' st oids = withSocketsDo $ do
    full <- packet st (toEmptySuite oids) GetNextRequest
    sendPacket st full
    packet <-  decryptPacketWithCache st =<< returnResult st
    checkError packet
    return $ getSuite packet

set' :: ST -> Suite -> IO Suite
set' st suite = withSocketsDo $ do
    full <- packet st suite SetRequest
    sendPacket st full
    packet <-  decryptPacketWithCache st =<< returnResult st
    checkError packet
    return $ getSuite packet

walk' :: ST -> OID -> OID -> Suite -> IO Suite
walk' st oids base accumulator  
    | oids == base = do
        first <- get' st [oids]
        next <- getnext' st [oids]
        case (first, next) of
             (Suite [Coupla _ NoSuchObject], Suite [Coupla nextOid _]) -> walk' st nextOid base next
             (Suite [Coupla _ NoSuchInstance], Suite [Coupla nextOid _]) -> walk' st nextOid base next
             (Suite [Coupla _ EndOfMibView], _) -> return accumulator
             (_, Suite [Coupla nextOid _]) -> walk' st nextOid base first
    | otherwise = do
        nextData <- getnext' st [oids]
        let Suite [Coupla next v] = nextData
        case (isUpLevel next base, v) of
             (True, _) -> return accumulator
             (_, NoSuchObject) -> walk' st next base accumulator
             (_, NoSuchInstance) -> walk' st next base accumulator
             (_, EndOfMibView) -> return accumulator
             (_, _) -> walk' st next base (accumulator <> nextData) 

bulkwalk' :: ST -> OID -> OID -> Suite -> IO Suite
bulkwalk' st oids base accumulator = do
       first <- bulkget' st [oids]
       let Coupla next snmpData = lastS first
           filtered (Suite xs) = Suite $ filter (\(Coupla x _) -> not $ isUpLevel x base) xs
       case (isUpLevel next base , snmpData) of
            (_, EndOfMibView) -> return $ accumulator <> filtered first
            (False, _) -> bulkwalk' st next base (accumulator <> first)
            (True, _) -> return $ accumulator <> filtered first
     
checkError :: Packet -> IO ()
checkError p = when (getErrorStatus p /= 0) $ throwIO $ ServerException $ getErrorStatus p

toEmptySuite :: OIDS -> Suite
toEmptySuite = Suite . map (\x -> Coupla x Zero) 

packet :: ST -> Suite -> (RequestId -> ErrorStatus -> ErrorIndex -> Request) -> IO Packet
packet st suite r = do
    rid <- predCounter (ref' st)
    eid' <- readIORef (engine' st)
    (eid, boots, time) <- case eid' of
                                Just x -> return x
                                Nothing -> init' st
    let wrapBulk (GetBulk rid x y) = GetBulk rid x 10
        wrapBulk x = x
        full = ( (setReportableP True) 
               . (setPrivAuthP (securityLevel' st)) 
               . (setUserNameP (login' st))  
               . (setEngineIdP eid)
               . (setEngineBootsP boots)
               . (setEngineTimeP time)
               . (setAuthenticationParametersP cleanPass)  
               . (setIDP (ID rid))
               . (setRequest $ wrapBulk (r rid 0 0))
               . (setSuite  suite)
               ) v3
    return full


sendPacket :: ST -> Packet -> IO ()
sendPacket st packet = sendAll (socket' st) . encode
      =<< signPacketWithCache st 
      =<< encryptPacketWithCache st packet

returnResult :: ST -> IO Packet
returnResult st = do
    result <- race (threadDelay (timeout' st)) (decode <$> recv (socket' st) 1500 :: IO Packet)
    case result of
         Right resp -> return resp
         Left _ -> throwIO TimeoutException

signPacketWithCache :: ST -> Packet -> IO Packet
signPacketWithCache st packet = do
    k <- readIORef (authCache' st)
    maybe (newKey packet) (reuseKey packet) k
    where
    newKey packet = do
        let key = passwordToKey (authType' st) (authPass' st) (getEngineIdP packet)
        atomicWriteIORef (authCache' st) (Just key)
        return $ signPacket (authType' st) key packet
    reuseKey packet key = return $ signPacket (authType' st) key packet

encryptPacketWithCache :: ST -> Packet -> IO Packet
encryptPacketWithCache st packet 
    | (securityLevel' st) == AuthPriv = do
        k <- readIORef (privCache' st)
        maybe (newKey packet) (reuseKey packet) k
    | otherwise = return packet
        where
          newKey packet = do
              s <- succCounter (saltInt' st)
              let key = passwordToKey (authType' st) (privPass' st) (getEngineIdP packet)
              atomicWriteIORef (privCache' st) (Just key)
              return $ encryptPacket (privType' st) key s packet  
          reuseKey packet key = do
              s <- succCounter (saltInt' st)
              return $ encryptPacket (privType' st) key s packet

decryptPacketWithCache :: ST -> Packet -> IO Packet
decryptPacketWithCache st packet = do
    k <- readIORef (privCache' st)
    maybe (newKey packet) (reuseKey packet) k
    where
    newKey packet = do
        let key = passwordToKey (authType' st) (privPass' st) (getEngineIdP packet)
        atomicWriteIORef (privCache' st) (Just key)
        return $ decryptPacket (privType' st) key packet
    reuseKey packet key = return $ decryptPacket (privType' st) key packet

