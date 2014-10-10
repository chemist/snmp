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
clientV3 hostname port timeout sequrityName authPass privPass sequrityLevel context authType privType = do
    socket <- trace "open socket" $ makeSocket hostname port 
    uniqInteger <- uniqID
    ref <- trace "init rid" $ newIORef uniqInteger
    authCache <- newIORef Nothing
    let 
        packet x = ( setIDP (ID x) 
                   . setMaxSizeP (MaxSize 65007) 
                   . setReportable False  
                   . setPrivAuth AuthNoPriv  
                   . setRid x 
                   ) v3
        get' oids = withSocketsDo $ do
            rid <- predCounter ref
            -- print (toASN1 (getrequest rid oids) [])
            sendAll socket $ encode $ packet rid
            -- putStr . show $ packet rid
            resp <- decode <$> recv socket 1500 :: IO Packet
            rid <- predCounter ref
            let  
                full = ( (setReportable True) 
                       . (setPrivAuth sequrityLevel) 
                       . (setUserName sequrityName)  
                       . (setAuthenticationParameters cleanPass)  
                       . (setIDP (ID rid))
                       . (setRequest (GetRequest rid 0 0))
                       . (setSuite  (Suite $ map (\x -> Coupla x Zero) oids))
                       ) resp
            putStr . show $ full
            sendAll socket . encode =<< signPacketWithCache authType authCache authPass full
--             sendAll socket . encode $ signPacket' authType authPass full
            -- print (getEngineId full)
            -- f <- signPacket authType authCache authPass full
            -- putStr . show $ f
            returnResult3 socket timeout
    return $ Client 
      { get = get' 
      , bulkget = undefined
      , getnext = undefined
      , walk = undefined
      , bulkwalk = undefined
      , set = undefined
      , close = trace "close socket" $ NS.close socket
      }

returnResult3 :: NS.Socket -> Int -> IO Suite
returnResult3 socket timeout = do
    result <- race (threadDelay timeout) (decode <$> recv socket 1500 :: IO Packet)
    case result of
         Right resp -> do
             when (0 /= getErrorStatus resp ) $ throwIO $ ServerException $ getErrorStatus resp
             return $ getSuite resp
         Left _ -> throwIO TimeoutException            
--     result <- decode <$> recv socket 1500 :: IO V3Packet
    -- let ee = fromASN1 result :: Either String (V3Packet, [ASN1])
--     putStr . show $ result 
--     return undefined 


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
 
