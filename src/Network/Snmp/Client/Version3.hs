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
import Data.Digest.Pure.MD5
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
            -- putStr . show $ full
            sendAll socket . encode =<< signPacket authCache authPass full
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

{--
 6.3.1. Processing an Outgoing Message

   This section describes the procedure followed by an SNMP engine
      whenever it must authenticate an outgoing message using the
         usmHMACMD5AuthProtocol.

   1) The msgAuthenticationParameters field is set to the serialization,
         according to the rules in [RFC3417], of an OCTET STRING containing
               12 zero octets.
--}

cleanPass = B.pack $ replicate 12 0x00

newtype AuthKey = AuthKey BL.ByteString deriving (Show, Eq, Ord)

testPass :: Password
testPass = "maplesyrup"

testEngineId :: ByteString
testEngineId = "\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\STX"

testAuthKey :: AuthKey
testAuthKey = AuthKey "Ro^\237\159\204\226o\137d\194\147\a\135\216+"

newtype ExtendAuthKey = ExtendAuthKey BL.ByteString deriving (Show, Eq, Ord)
newtype K1 = K1 BL.ByteString
newtype K2 = K2 BL.ByteString

signPacket :: IORef (Maybe AuthKey) -> Password -> Packet -> IO Packet
signPacket authCache authPass packet = do
    k <- readIORef authCache
    let key = case k of
                 Nothing -> makeAuthKeyMD5 authPass (getEngineId packet)
                 Just k -> k
    when (k == Nothing) $ atomicWriteIORef authCache (Just key)
    let sign = makeSign key packet
    return $ setAuthenticationParameters sign packet
    where
        ipad :: [Word8]
        ipad = replicate 64 0x36
        
        opad :: [Word8]
        opad = replicate 64 0x5c
        
        step2 :: AuthKey -> (K1, K2)
        step2 au = 
          let ExtendAuthKey ex = makeExtendAuthKey au
              k1 = K1 . BL.pack . map (uncurry xor) $ zip (BL.unpack ex) ipad
              k2 = K2 . BL.pack . map (uncurry xor) $ zip (BL.unpack ex) opad
          in (k1, k2)
        
        makeSign :: AuthKey -> Packet -> ByteString
        makeSign authKey p = 
          let (K1 k1, K2 k2) = step2 authKey
              packetAsBin = encode p
              f1 = Bin.encode $ md5 $ k1 <> BL.fromStrict packetAsBin
              f2 = Bin.encode $ md5 $ k2 <> f1
          in BL.toStrict $ BL.take 12 f2

        makeExtendAuthKey :: AuthKey -> ExtendAuthKey
        makeExtendAuthKey (AuthKey x) = ExtendAuthKey $ x <> BL.replicate 48 0x00
 
        makeAuthKeyMD5 :: Password -> ContextEngineID -> AuthKey
        makeAuthKeyMD5 pass (ContextEngineID eid) = 
          let buf = BL.take 1048576 $ BL.fromChunks $ repeat pass
              authKey = Bin.encode $ md5 buf
          in AuthKey <$> Bin.encode $ md5 $ authKey <> BL.fromStrict eid <> authKey
        
        authenticationParameterZero :: ASN1
        authenticationParameterZero = OctetString $ B.replicate 12 0

   


{--
            let key = makeAuthKeyMD5 authPass (getEngineId resp)
                sign = makeSign key full
                signedPacket = signPacket sign full

--}

{--

   2) From the secret authKey, two keys K1 and K2 are derived:

      a) extend the authKey to 64 octets by appending 48 zero octets;
               save it as extendedAuthKey

      b) obtain IPAD by replicating the octet 0x36 64 times;

      c) obtain K1 by XORing extendedAuthKey with IPAD;

      d) obtain OPAD by replicating the octet 0x5C 64 times;

      e) obtain K2 by XORing extendedAuthKey with OPAD.

   3) Prepend K1 to the wholeMsg and calculate MD5 digest over it
         according to [RFC1321].

   4) Prepend K2 to the result of the step 4 and calculate MD5 digest
         over it according to [RFC1321].  Take the first 12 octets of the
               final digest - this is Message Authentication Code (MAC).

   5) Replace the msgAuthenticationParameters field with MAC obtained in
         the step 4.




Blumenthal & Wijnen         Standards Track                    [Page 55]
 
RFC 3414                     USM for SNMPv3                December 2002


   6) The authenticatedWholeMsg is then returned to the caller together
         with statusInformation indicating success.

--}
