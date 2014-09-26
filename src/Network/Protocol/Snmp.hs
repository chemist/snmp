{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleInstances #-}
module Network.Protocol.Snmp 
( Version(..)
, SnmpData(..)
, Community(..)
, Request(..)
, PDU(..)
, RequestId
, SnmpPacket(..)
, Header(..)
, encode
, decode
)
where

import Data.ASN1.Parse
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ByteString (ByteString, pack, unpack)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Control.Applicative
import Network.Protocol.Simple
import Data.Monoid
import Data.Bits
import Data.Word
import Debug.Trace

newtype Community = Community ByteString deriving (Show, Eq)
type RequestId = Integer
type ErrorStatus = Integer
type ErrorIndex = Integer

data Version = Version1
             | Version2
             | Version3
             deriving (Show, Eq)

data Request = GetRequest RequestId ErrorStatus ErrorIndex 
             | GetNextRequest RequestId ErrorStatus ErrorIndex 
             | GetResponse RequestId ErrorStatus ErrorIndex  
             | SetRequest RequestId ErrorStatus ErrorIndex 
             | GetBulk RequestId ErrorStatus ErrorIndex 
             | Inform
             | V2Trap
             | Report
             deriving (Show, Eq)

data PDU = PDU Request SnmpData deriving (Show, Eq)

data SnmpData = SnmpData [(OID, SnmpType)] deriving (Eq)

instance Monoid SnmpData where
    mempty = SnmpData []
    mappend (SnmpData xs) (SnmpData ys) = SnmpData $ xs <> ys

instance Show SnmpData where
    show (SnmpData xs) = unlines $ map (\(oid, snmptype) -> oidToString oid ++ " = " ++ show snmptype) xs

oidToString :: OID -> String
oidToString xs = foldr1 (\x y -> x ++ "." ++ y) $ map show xs

data SnmpPacket a = SnmpPacket Header a 
                deriving (Show, Eq)

data Header = Header Version (Maybe V3Context) (Maybe Community)
            deriving (Show, Eq)

instance ASN1Object Header where
    toASN1 (Header Version3 (Just context) _) xs = IntVal 3 : (toASN1 context xs)
    toASN1 (Header Version1 _ (Just (Community community))) xs = IntVal 0 : OctetString community : xs
    toASN1 (Header Version2 _ (Just (Community community))) xs = IntVal 1 : OctetString community : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        case x of
             0 -> Header Version1 Nothing <$> Just <$> getObject
             1 -> Header Version2 Nothing <$> Just <$> getObject
             3 -> Header Version3 <$> Just <$> getObject <*> pure Nothing

instance ASN1Object Community where
    toASN1 (Community x) xs = OctetString x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        OctetString x <- getNext
        return $ Community x

data V3Context = V3Context MsgID MsgMaxSize MsgFlag MsgSecurityModel MsgSecurityParameter deriving (Show, Eq)

-- testHeader = Header Version3 (Just $ V3Context (MsgID 1000) (MsgMaxSize 65000) (MsgFlag False AuthNoPriv) UserBasedSecurityModel)

instance ASN1Object V3Context where
    toASN1 (V3Context msgId msgMaxSize msgFlag msgSecurityModel msgSecurityParameter) xs = 
      Start Sequence : toASN1 msgId (toASN1 msgMaxSize (toASN1 msgFlag (toASN1 msgSecurityModel [End Sequence]))) ++ toASN1 msgSecurityParameter xs
    fromASN1 asn = flip runParseASN1State asn $ do
        Start Sequence <- getNext
        msgId <- getObject
        msgMaxSize <- getObject
        msgFlag <- getObject
        msgSecurityModel <- getObject
        End Sequence <- getNext
        msgSecurityParameter <- getObject
        return $ V3Context msgId msgMaxSize msgFlag msgSecurityModel msgSecurityParameter

-- Message Identifier (like RequestId in PDU)
newtype MsgID = MsgID Integer deriving (Show, Eq)

instance ASN1Object MsgID where
    toASN1 (MsgID x) xs = IntVal x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        return $ MsgID x

-- Message max size must be > 484
newtype MsgMaxSize = MsgMaxSize Integer deriving (Show, Eq)

instance ASN1Object MsgMaxSize where
    toASN1 (MsgMaxSize x) xs = IntVal x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        return $ MsgMaxSize x

data MsgFlag = MsgFlag Reportable PrivAuth deriving (Show, Eq)

data PrivAuth = NoAuthNoPriv | AuthNoPriv | AuthPriv deriving (Show, Eq)

type Reportable = Bool

instance ASN1Object MsgFlag where
    toASN1 (MsgFlag r pa) xs = let zero = zeroBits :: Word8
                                   reportable = if r then setBit zero 0 else zero
                                   privauth = case pa of
                                                   NoAuthNoPriv -> zero
                                                   AuthNoPriv -> setBit zero 2
                                                   AuthPriv -> setBit zero 1 .|. setBit zero 2
                                   flag = reportable .|. privauth
                                in OctetString (pack [flag]) : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        OctetString x <- getNext
        let [w] = unpack x
        return $ case (testBit w 1, testBit w 2) of
                      (True, True) -> MsgFlag (testBit w 0) AuthPriv
                      (False, False) -> MsgFlag (testBit w 0) NoAuthNoPriv
                      (False, True) -> MsgFlag (testBit w 0) AuthNoPriv
                      _ -> error "bad flag"

data MsgSecurityModel = UserBasedSecurityModel deriving (Show, Eq)

instance ASN1Object MsgSecurityModel where
    toASN1 UserBasedSecurityModel xs = IntVal 3 : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        case x of
             3 -> return UserBasedSecurityModel
             _ -> error "other security model"

data MsgSecurityParameter = MsgSecurityParameter 
  { msgAuthoritiveEngineId :: ByteString
  , msgAuthoritiveEngineBoots :: Integer
  , msgAuthoritiveEngineTime :: Integer
  , msgUserName :: ByteString
  , msgAuthenticationParameters :: ByteString
  , msgPrivacyParameters :: ByteString
  }
  deriving (Show, Eq)

instance ASN1Object MsgSecurityParameter where
    toASN1 MsgSecurityParameter{..} xs = OctetString (encodeASN1' DER
      [ Start Sequence
      ,   OctetString msgAuthoritiveEngineId 
      ,   IntVal msgAuthoritiveEngineBoots
      ,   IntVal msgAuthoritiveEngineTime
      ,   OctetString msgUserName 
      ,   OctetString msgAuthenticationParameters
      ,   OctetString msgPrivacyParameters
      , End Sequence
      ]) : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        OctetString packed <- getNext
        let a = decodeASN1' DER packed
        case a of
             Left e -> error $ show e
             Right as -> do
                 Start Sequence <- getNext
                 OctetString msgAuthoritiveEngineId <- getNext
                 IntVal msgAuthoritiveEngineBoots <- getNext
                 IntVal msgAuthoritiveEngineTime <- getNext
                 OctetString msgUserName <- getNext
                 OctetString msgAuthenticationParameters <- getNext
                 OctetString msgPrivacyParameters <- getNext
                 End Sequence <- getNext
                 return $ MsgSecurityParameter msgAuthoritiveEngineId msgAuthoritiveEngineBoots msgAuthoritiveEngineTime msgUserName msgAuthenticationParameters msgPrivacyParameters 

data ScopedPDU = ScopedPDU ContextEngineID ContextName PDU deriving (Show, Eq)

instance ASN1Object ScopedPDU where
    toASN1 (ScopedPDU (ContextEngineID x) (ContextName y) pdu) xs = 
      [Start Sequence, OctetString x, OctetString y] ++ (toASN1 pdu xs)
    fromASN1 asn = flip runParseASN1State asn $ do
        Start Sequence <- getNext
        OctetString x <- getNext
        OctetString y <- getNext
        pdu <- getObject
        End Sequence <- getNext
        return $ ScopedPDU (ContextEngineID x) (ContextName y) pdu

newtype ContextEngineID = ContextEngineID ByteString deriving (Show, Eq)

newtype ContextName = ContextName ByteString deriving (Show, Eq)

msgSecParB :: ByteString
msgSecParB = "0\SO\EOT\NUL\STX\SOH\NUL\STX\SOH\NUL\EOT\NUL\EOT\NUL\EOT\NUL"
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
instance ASN1Object Request where
    toASN1 (GetRequest rid _ _    ) xs = (Start $ Container Context 0):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : xs ++ [ End Sequence, End (Container Context 0)]
    toASN1 (GetNextRequest rid _ _) xs = (Start $ Container Context 1):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : xs ++ [ End Sequence, End (Container Context 1)]
    toASN1 (GetResponse rid es ei ) xs = (Start $ Container Context 2):IntVal rid : IntVal es : IntVal ei: Start Sequence : xs ++ [ End Sequence, End (Container Context 2)]
    toASN1 (SetRequest rid _ _    ) xs = (Start $ Container Context 3):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : xs ++ [ End Sequence, End (Container Context 3)]
    toASN1 (GetBulk rid es ei     ) xs = (Start $ Container Context 5):IntVal rid : IntVal es : IntVal ei: Start Sequence : xs ++ [ End Sequence, End (Container Context 4)]
    toASN1 _ _ = error "not inplemented"
    fromASN1 asn = 
      case fromASN1Request asn of
           Left e -> Left e
           Right (r, _) -> Right r


fromASN1Request :: [ASN1] -> Either String ((Request, [ASN1]), [ASN1])
fromASN1Request asn = flip runParseASN1State asn $ do
        Start container <- getNext
        IntVal rid <- getNext
        IntVal es <- getNext
        IntVal ei <- getNext
        x <- getNextContainer Sequence
        End container' <- getNext
        case (container == container', container) of
             (True, Container Context 0) -> return (GetRequest rid es ei, x)
             (True, Container Context 1) -> return (GetNextRequest rid es ei, x)
             (True, Container Context 2) -> return (GetResponse rid es ei, x)
             (True, Container Context 3) -> return (SetRequest rid es ei, x)
             (True, Container Context 5) -> return (GetBulk rid es ei, x)
             _ -> error "not inplemented or bad sequence"

instance ASN1Object SnmpData where
    toASN1 (SnmpData xs) ys = foldr toA [] xs ++ ys
      where 
      toA ::(OID,SnmpType) -> [ASN1] -> [ASN1]
      toA (o, v) zs = [Start Sequence , OID o] ++ toASN1 v (End Sequence : zs)
    fromASN1 asn = flip runParseASN1State asn $ do
        xs <- getMany $ do
               Start Sequence <- getNext
               OID x <- getNext
               v <-  getObject
               End Sequence <- getNext
               return (x, v)
        return $ SnmpData xs

instance ASN1Object PDU where
    toASN1 (PDU r sd) xs = toASN1 r (toASN1 sd []) ++  xs
    fromASN1 asn = flip runParseASN1State asn $ do
        r <- getObject 
        sd <- getObject
        return $ PDU r sd

instance ASN1Object (SnmpPacket PDU) where
    toASN1 (SnmpPacket header pdu) _ = 
      Start Sequence : ( toASN1 header ( toASN1 pdu [End Sequence]))
   
    fromASN1 asn = flip runParseASN1State asn $ onNextContainer Sequence $ do
        header@(Header v c s) <- getObject
        pdu <- getObject
        case v of
             Version1 -> return $ SnmpPacket header pdu 
             Version2 -> return $ SnmpPacket header pdu 

instance ASN1Object (SnmpPacket ScopedPDU) where
    toASN1 (SnmpPacket header pdu) _ = 
      Start Sequence : ( toASN1 header ( toASN1 pdu [End Sequence]))

    fromASN1 asn = flip runParseASN1State asn $ onNextContainer Sequence $ do
        header@(Header v c s) <- getObject
        pdu <- getObject
        case v of
             Version3 -> return $ SnmpPacket header pdu 

class Pack a where
    encode :: a -> ByteString
    decode :: ByteString -> a

instance Pack (SnmpPacket ScopedPDU) where
    encode s = encodeASN1' DER $ toASN1 s []
    decode = toB3

instance Pack (SnmpPacket PDU) where
    encode s = encodeASN1' DER $ toASN1 s []
    decode = toB 

toB :: ByteString -> (SnmpPacket PDU)
toB bs = let a = fromASN1 <$> decodeASN1' DER bs
         in case a of
                 Right (Right (r, _)) -> r
                 _ -> error "bad packet"

toB3 :: ByteString -> (SnmpPacket ScopedPDU)
toB3 bs = let a = fromASN1 <$> decodeASN1' DER bs
          in case a of
                 Right (Right (r, _)) -> r
                 _ -> error "bad packet"
