{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Network.Snmp.Client.Version3 
( clientV3
, msg
)
where

import Data.ByteString (ByteString)
import Network.Socket hiding (recv, socket, close)
import qualified Network.Socket as NS
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Control.Applicative ((<$>))
import Control.Concurrent.Async
import Data.IORef (newIORef)
import Control.Concurrent (threadDelay)
import Control.Monad (when)
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types hiding (Context) 
import Debug.Trace

import Network.Protocol.Snmp
import Network.Snmp.Client.Types
import Network.Snmp.Client.Internal 

clientV3 :: Hostname -> Port -> Int -> Login -> Password -> Password -> PrivAuth -> ByteString -> AuthType -> PrivType -> IO Client
clientV3 hostname port timeout sequrityName authPass privPass sequrityLevel context authType privType = do
    socket <- trace "open socket" $ makeSocket hostname port 
    ref <- trace "init rid" $ newIORef 0
    let 
        contextP = Context (MsgID 1062299988) (MsgMaxSize 65507) (MsgFlag False sequrityLevel) UserBasedSecurityModel $
           MsgSecurityParameter "" 0 0 "" "" ""   
        getrequest rid oids = 
            SnmpPacket (Header Version3 contextP) $
                ScopedPDU (ContextEngineID "") (ContextName "") $
                    PDU (GetRequest 1186729734 0 0) (Suite [])

        get' oids = withSocketsDo $ do
            rid <- succRequestId ref
            -- print (toASN1 (getrequest rid oids) [])
            sendAll socket $ encode $ getrequest rid oids
            putStr . show $ getrequest rid oids
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
    result <- decode <$> recv socket 1500 :: IO V3Packet
    -- let ee = fromASN1 result :: Either String (V3Packet, [ASN1])
    putStr . show $ result 
    return undefined 

msg :: ByteString
msg = "03\EOT\DC1\128\NUL\US\136\128v\224\131\SI|\155\SUBT\NUL\NUL\NUL\NUL\STX\SOH6\STX\STX\NUL\156\EOT\achemist\EOT\f\STX\162gZ\189\158 \151\182\DEL,\249\EOT\NUL"

{--
second request

[Start Sequence
  ,IntVal 3
  ,Start Sequence
    ,IntVal 1416337610
    ,IntVal 65507
    ,OctetString "\ENQ"
    ,IntVal 3
  ,End Sequence
  ,OctetString "03\EOT\DC1\128\NUL\US\136\128v\224\131\SI|\155\SUBT\NUL\NUL\NUL\NUL\STX\SOH6\STX\STX\NUL\156\EOT\achemist\EOT\f\STX\162gZ\189\158 \151\182\DEL,\249\EOT\NUL"
  ,Start Sequence
    ,OctetString "\128\NUL\US\136\128v\224\131\SI|\155\SUBT\NUL\NUL\NUL\NUL"
    ,OctetString ""
    ,Start (Container Context 0)
      ,IntVal 194066496
      ,IntVal 0
      ,IntVal 0
      ,Start Sequence
        ,Start Sequence
          ,OID [1,3,6,1,2,1,25,1,1,0]
          ,Null
        ,End Sequence
      ,End Sequence
    ,End (Container Context 0)
  ,End Sequence
,End Sequence]

MsgSequrityParameter
[Start Sequence
  ,OctetString "\128\NUL\US\136\128v\224\131\SI|\155\SUBT\NUL\NUL\NUL\NUL"
  ,IntVal 54
  ,IntVal 156
  ,OctetString "chemist"
  ,OctetString "\STX\162gZ\189\158 \151\182\DEL,\249"
  ,OctetString ""
,End Sequence]



[Start Sequence,OctetString "",IntVal 0,IntVal 0,OctetString "",OctetString "",OctetString "",End Sequence]

[Start Sequence
  ,IntVal 3
  ,Start Sequence
    ,IntVal 1062299988
    ,IntVal 65507
    ,OctetString "\NUL"
    ,IntVal 3
  ,End Sequence
  ,OctetString "0!\EOT\DC1\128\NUL\US\136\128v\224\131\SI|\155\SUBT\NUL\NUL\NUL\NUL\STX\SOH\DC1\STX\ETX\ACKI%\EOT\NUL\EOT\NUL\EOT\NUL"
  ,Start Sequence
    ,OctetString "\128\NUL\US\136\128v\224\131\SI|\155\SUBT\NUL\NUL\NUL\NUL"
    ,OctetString ""
    ,Start (Container Context 8)
      ,IntVal 1186729734
      ,IntVal 0
      ,IntVal 0
      ,Start Sequence
        ,Start Sequence
          ,OID [1,3,6,1,6,3,15,1,1,4,0]
          ,Other Application 1 "7"
        ,End Sequence
      ,End Sequence
    ,End (Container Context 8)
  ,End Sequence
,End Sequence]

000: 30 3E 02 01  03 30 11 02  04 44 1E 7D  C2 02 03 00    0>...0...D.}�...
0016: FF E3 04 01  04 02 01 03  04 10 30 0E  04 00 02 01    ��........0.....
0032: 00 02 01 00  04 00 04 00  04 00 30 14  04 00 04 00    ..........0.....
0048: A0 0E 02 04  1B 2A 31 79  02 01 00 02  01 00 30 00    �....*1y......0.


[Start Sequence
  ,IntVal 3
  ,Start Sequence
    ,IntVal 1062299987
    ,IntVal 65507
    ,OctetString "\EOT"
    ,IntVal 3
  ,End Sequence
  ,OctetString "0\SO\EOT\NUL\STX\SOH\NUL\STX\SOH\NUL\EOT\NUL\EOT\NUL\EOT\NUL"
  ,Start Sequence
    ,OctetString ""
    ,OctetString ""
    ,Start (Container Context 0)
      ,IntVal 1186729734
      ,IntVal 0
      ,IntVal 0
      ,Start Sequence
      ,End Sequence
    ,End (Container Context 0)
  ,End Sequence
,End Sequence]
                --}



{--
returnResult3 :: NS.Socket -> Int -> IO Suite
returnResult3 socket timeout = do
    result <- race (threadDelay timeout) (decode <$> recv socket 1500 :: IO V3Packet)
    case result of
         Right (SnmpPacket (Header v c) (ScopedPDU ceid cn (PDU (GetResponse rid e ie) d))) -> do
             when (e /= 0) $ throwIO $ ServerException e
             return d
         Left _ -> throwIO TimeoutException            
         --}
