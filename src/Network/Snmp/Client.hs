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
, Coupla(..)
, Suite(..)
, Value(String, Integer, IpAddress, Counter32, Gaude32, TimeTicks, Opaque, Counter64, ZeroDotZero, Zero)
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
import Network.Snmp.Client.Types
import Control.Concurrent.Async
import Data.IORef
import Control.Concurrent (threadDelay)
import Control.Exception
import Data.Typeable
import Control.Monad (when)
import Data.Monoid
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types hiding (Context) 
import Debug.Trace

defConfig Version1 = ConfigV2 "localhost" "161" (sec 5) (Community "public") 
defConfig Version2 = ConfigV2 "localhost" "161" (sec 5) (Community "public")
defConfig Version3 = ConfigV3 "localhost" "161" (sec 5) "guest" "readonly"

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

returnResult2 :: NS.Socket -> Int -> IO Suite
returnResult2 socket timeout = do
    result <- race (threadDelay timeout) (decode <$> recv socket 1500 :: IO V2Packet)
    case result of
         Right (SnmpPacket _ (PDU (GetResponse rid e ie) d)) -> do
             when (e /= 0) $ throwIO $ ServerException e
             return d
         Left _ -> throwIO TimeoutException            

client :: Config -> IO Client
client ConfigV2{..} = do
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

client ConfigV3{..} = do
    socket <- trace "open socket" $ makeSocket hostname port 
    ref <- trace "init rid" $ newIORef 0
    let 
        context = Context (MsgID 1062299988) (MsgMaxSize 65000) (MsgFlag False AuthNoPriv) UserBasedSecurityModel $
           MsgSecurityParameter "" 0 0 "" "" ""   
        getrequest rid oids = 
            SnmpPacket (Header Version3 context) $
                ScopedPDU (ContextEngineID "") (ContextName "") $
                    PDU (GetRequest 1186729734 0 0) (Suite [])

        get' oids = withSocketsDo $ do
            rid <- succRequestId ref
            -- print (toASN1 (getrequest rid oids) [])
            sendAll socket $ encode $ getrequest rid oids
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
    result <- decodeASN1' DER <$> recv socket 1500
    print result
    return undefined
{--
[Start Sequence,OctetString "",IntVal 0,IntVal 0,OctetString "",OctetString "",OctetString "",End Sequence]
--}

{--
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

lastS :: Suite -> Coupla
lastS (Suite xs) = last xs

isUpLevel :: OID -> OID -> Bool
isUpLevel new old = let baseLength = length old
                    in old /= take baseLength new 
