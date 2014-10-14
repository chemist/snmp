{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
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
import Data.Monoid ((<>), mempty)
import Data.Bits (xor)
import Data.Word (Word8)
import Control.Exception 
import Debug.Trace

import Network.Protocol.Snmp
import Network.Snmp.Client.Types
import Network.Snmp.Client.Internal 

v3 :: Packet 
v3 = initial Version3 

clientV3 :: Hostname -> Port -> Int -> Login -> Password -> Password -> PrivAuth -> ByteString -> AuthType -> PrivType -> IO Client
clientV3 hostname port timeout sequrityName authPass privPass securityLevel context authType privType = do
    socket <- makeSocket hostname port 
    uniqInteger <- uniqID
    ref <- newIORef uniqInteger
    authCache <- newIORef Nothing
    privCache <- newIORef Nothing
    let 
        packet x = ( setIDP (ID x) 
                   . setMaxSizeP (MaxSize 65007) 
                   . setReportable False  
                   . setPrivAuth AuthNoPriv  
                   . setRid x 
                   ) v3
        get' oids = withSocketsDo $ do
            rid <- predCounter ref
            sendAll socket $ encode $ packet rid
            resp <- decode <$> recv socket 1500 :: IO Packet
            rid <- predCounter ref
            let  
                full = ( (setReportable True) 
                       . (setPrivAuth securityLevel) 
                       . (setUserName sequrityName)  
                       . (setAuthenticationParameters cleanPass)  
                       . (setIDP (ID rid))
                       . (setRequest (GetRequest rid 0 0))
                       . (setSuite  (Suite $ map (\x -> Coupla x Zero) oids))
                       ) resp
            sendAll socket . encode 
              =<< signPacketWithCache authType authCache authPass 
              =<< encryptPacketWithCache securityLevel authType privType privCache privPass full
            packet <-  decryptPacketWithCache authType privType privCache privPass =<< returnResult socket (sec 5)
            return $ getSuite packet
    return $ Client 
      { get = get' 
      , bulkget = undefined
      , getnext = undefined
      , walk = undefined
      , bulkwalk = undefined
      , set = undefined
      , close = NS.close socket
      }

returnResult :: NS.Socket -> Int -> IO Packet
returnResult socket timeout = do
    result <- race (threadDelay timeout) (decode <$> recv socket 1500 :: IO Packet)
    case result of
         Right resp -> return resp
         Left _ -> throwIO TimeoutException


signPacketWithCache :: AuthType -> IORef (Maybe Key) -> Password -> Packet -> IO Packet
signPacketWithCache authType authCache authPass packet = do
    k <- readIORef authCache 
    maybe (newKey authType authCache authPass packet) (reuseKey authType packet) k
    where 
    newKey at authCache authPass packet = do
        let key = passwordToKey at authPass (getEngineId packet)
        atomicWriteIORef authCache (Just key)
        return $ signPacket at key packet
    reuseKey at packet key = return $ signPacket at key packet
 
encryptPacketWithCache :: PrivAuth -> AuthType -> PrivType -> IORef (Maybe Key) -> Password -> Packet -> IO Packet
encryptPacketWithCache AuthPriv authType privType privCache privPass packet = do
    k <- readIORef privCache
    maybe (newKey authType privType privCache privPass packet) (reuseKey privType packet) k
    where
    newKey at privType privCache privPass packet = do
        let key = passwordToKey at privPass (getEngineId packet)
        atomicWriteIORef privCache (Just key)
        return $ encryptPacket privType key packet  
    reuseKey privType packet key = return $ encryptPacket privType key packet
encryptPacketWithCache _ _ _ _ _ p = return p

decryptPacketWithCache :: AuthType -> PrivType -> IORef (Maybe Key) -> Password -> Packet -> IO Packet
decryptPacketWithCache authType privType privCache privPass packet = do
    k <- readIORef privCache
    maybe (newKey authType privType privCache privPass packet) (reuseKey privType packet) k
    where
    newKey at privType privCache privPass packet = do
        let key = passwordToKey at privPass (getEngineId packet)
        atomicWriteIORef privCache (Just key)
        return $ decryptPacket privType key packet
    reuseKey privType packet key = return $ decryptPacket privType key packet


