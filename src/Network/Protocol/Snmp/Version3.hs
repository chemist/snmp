{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Network.Protocol.Snmp.Version3 where
import Data.ASN1.Encoding
import Data.ASN1.Types hiding (Context)
import Data.ASN1.Parse
import Data.ASN1.BinaryEncoding
import Network.Protocol.Snmp.Types
import Control.Applicative
import Data.Bits
import Data.Word
import Data.ByteString (ByteString, pack, unpack)
import Debug.Trace


data Context = Context MsgID MsgMaxSize MsgFlag MsgSecurityModel MsgSecurityParameter deriving (Eq)

instance Show Context where
    show (Context msgID msgMaxSize msgFlag msgSecurityModel msgSecurityParameter) = 
      "context:\n\t" ++ show msgID 
      ++ "\n\t" ++ show msgMaxSize 
      ++ "\n\t" ++ show msgFlag 
      ++ "\n\t" ++ show msgSecurityModel 
      ++ "\n\t" ++ show msgSecurityParameter

-- testHeader = Header Version3 (Just $ V3Context (MsgID 1000) (MsgMaxSize 65000) (MsgFlag False AuthNoPriv) UserBasedSecurityModel)

instance ASN1Object Context where
    toASN1 (Context msgId msgMaxSize msgFlag msgSecurityModel msgSecurityParameter) xs = 
      Start Sequence : toASN1 msgId (toASN1 msgMaxSize (toASN1 msgFlag (toASN1 msgSecurityModel [End Sequence]))) ++ toASN1 msgSecurityParameter xs
    fromASN1 asn = flip runParseASN1State asn $ do
        Start Sequence <- getNext
        msgId <- getObject
        msgMaxSize <- getObject
        msgFlag <- getObject
        msgSecurityModel <- getObject
        End Sequence <- getNext
        msgSecurityParameter <- getObject
        return $ Context msgId msgMaxSize msgFlag msgSecurityModel msgSecurityParameter

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
  deriving (Eq)

instance Show MsgSecurityParameter where
    show msg = "MsgSecurityParameter:\n\t\tAuthoritiveEngineId: " 
       ++ show (msgAuthoritiveEngineId msg)
       ++ "\n\t\tAuthoritiveEngineBoots: " ++ show (msgAuthoritiveEngineBoots msg)
       ++ "\n\t\tAuthoritiveEngineTime: " ++ show (msgAuthoritiveEngineTime msg)
       ++ "\n\t\tUserName: " ++ show (msgUserName msg)
       ++ "\n\t\tAuthenticationParameters: " ++ show (msgAuthenticationParameters msg)
       ++ "\n\t\tPrivacyParameters: " ++ show (msgPrivacyParameters msg)

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
        let r = case decodeASN1' DER packed of
             Left e -> error $ "cant unpack msgSecurity parameter " ++ show e
             Right asn' -> parseMsgSecurityParameter asn'
        case r of
             Left e -> error $ "cant parse msgSecurity parameter" ++ show e
             Right r -> return r

parseMsgSecurityParameter :: [ASN1] -> Either String MsgSecurityParameter
parseMsgSecurityParameter asn = flip runParseASN1 asn $ do
     Start Sequence <- getNext
     OctetString msgAuthoritiveEngineId <- getNext
     IntVal msgAuthoritiveEngineBoots <- getNext
     IntVal msgAuthoritiveEngineTime <- getNext
     OctetString msgUserName <- getNext
     OctetString msgAuthenticationParameters <- getNext
     OctetString msgPrivacyParameters <- getNext
     End Sequence <- getNext
     return $ MsgSecurityParameter msgAuthoritiveEngineId msgAuthoritiveEngineBoots msgAuthoritiveEngineTime msgUserName msgAuthenticationParameters msgPrivacyParameters 

data ScopedPDU = ScopedPDU ContextEngineID ContextName PDU deriving (Eq)

instance Show ScopedPDU where
    show (ScopedPDU ceid cn pdu) = "ScopedPDU\n\t" ++ show ceid ++ "\n\t" ++ show cn ++ "\n\t" ++ show pdu ++ "\n"

instance ASN1Object ScopedPDU where
    toASN1 (ScopedPDU (ContextEngineID x) (ContextName y) pdu) xs = 
      [Start Sequence, OctetString x, OctetString y] ++ (toASN1 pdu (End Sequence :xs))
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

