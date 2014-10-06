{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
module Network.Protocol.Snmp.Version3 
( MsgID(..)
, MsgMaxSize(..)
, PrivAuth(..)
, Reportable
, MsgFlag
, MsgSecurityModel(..)
, MsgSecurityParameter
, HeaderData
, ScopedPDU(..)
, ContextName(..)
, ContextEngineID(..)
-- ^ lenses
, reportable
, privAuth
, msgAuthoritiveEngineId
, msgPrivacyParameters
, msgAuthoritiveEngineTime
, msgAuthoritiveEngineBoots
, msgAuthenticationParameters
, msgSecurityParameter
, pdu
, msgFlag
, msgUserName
, contextEngineId
, msgId
, msgMaxSize
)
where
import Data.ASN1.Encoding
import Data.ASN1.Types hiding (Context)
import Data.ASN1.Parse
import Data.ASN1.BinaryEncoding
import Network.Protocol.Snmp.Types
import Control.Applicative
import Data.Bits
import Data.Word
import Data.ByteString (ByteString, pack, unpack)
import Data.Monoid
import Control.Lens
import Debug.Trace

-- Message Identifier (like RequestId in PDU)
newtype MsgID = MsgID Integer deriving (Show, Eq)

deriving instance Monoid MsgID

-- Message max size must be > 484
newtype MsgMaxSize = MsgMaxSize Integer deriving (Show, Eq)

deriving instance Monoid MsgMaxSize

data PrivAuth = NoAuthNoPriv | AuthNoPriv | AuthPriv deriving (Show, Eq)

instance Monoid PrivAuth where
    mempty = NoAuthNoPriv
    mappend _ x = x

type Reportable = Bool

data MsgFlag = MsgFlag { _reportable :: Reportable, _privAuth :: PrivAuth } deriving (Show, Eq)

instance Monoid MsgFlag where
    mempty = MsgFlag False mempty
    mappend (MsgFlag True x) (MsgFlag _ y) = MsgFlag True (x <> y)
    mappend (MsgFlag _ x) (MsgFlag True y) = MsgFlag True (x <> y)
    mappend (MsgFlag False x) (MsgFlag False y) = MsgFlag True (x <> y)

makeLenses ''MsgFlag

data MsgSecurityModel = UserBasedSecurityModel deriving (Show, Eq)

instance Monoid MsgSecurityModel where
    mempty = UserBasedSecurityModel
    mappend _ _ = UserBasedSecurityModel

data MsgSecurityParameter = MsgSecurityParameter 
  { _msgAuthoritiveEngineId :: ByteString
  , _msgAuthoritiveEngineBoots :: Integer
  , _msgAuthoritiveEngineTime :: Integer
  , _msgUserName :: ByteString
  , _msgAuthenticationParameters :: ByteString
  , _msgPrivacyParameters :: ByteString
  }
  deriving (Eq)

instance Monoid Integer where
    mempty = 0
    mappend = (+)

instance Monoid MsgSecurityParameter where
    mempty = MsgSecurityParameter "" 0 0 "" "" ""
    mappend (MsgSecurityParameter a0 b0 c0 d0 e0 f0) 
            (MsgSecurityParameter a1 b1 c1 d1 e1 f1) 
            = MsgSecurityParameter (a0 <> a1) (b0 <> b1) (c0 <> c1) (d0 <> d1) (e0 <> e1) (f0 <> f1)

makeLenses ''MsgSecurityParameter


data HeaderData = HeaderData 
  { _msgId :: MsgID 
  , _msgMaxSize :: MsgMaxSize
  , _msgFlag :: MsgFlag 
  , _msgSecurityModel :: MsgSecurityModel 
  , _msgSecurityParameter :: MsgSecurityParameter
  } deriving (Eq)

instance Monoid HeaderData where
    mempty = HeaderData mempty mempty mempty mempty mempty
    mappend (HeaderData a0 b0 c0 d0 e0)
            (HeaderData a1 b1 c1 d1 e1) 
            = HeaderData (a0 <> a1) (b0 <> b1) (c0 <> c1) (d0 <> d1) (e0 <> e1)

makeLenses ''HeaderData

instance Show HeaderData where
    show msg = 
      "headerData:\n\t" ++ show ( msg ^. msgId )
      ++ "\n\t" ++ show ( msg ^. msgMaxSize)
      ++ "\n\t" ++ show ( msg ^.  msgFlag)
      ++ "\n\t" ++ show ( msg ^. msgSecurityModel )
      ++ "\n\t" ++ show ( msg ^. msgSecurityParameter)

-- testHeader = Header Version3 (Just $ V3Context (MsgID 1000) (MsgMaxSize 65000) (MsgFlag False AuthNoPriv) UserBasedSecurityModel)

instance ASN1Object HeaderData where
    toASN1 (HeaderData msgId msgMaxSize msgFlag msgSecurityModel msgSecurityParameter) xs = 
        Start Sequence : toASN1 msgId (toASN1 msgMaxSize (toASN1 msgFlag (toASN1 msgSecurityModel [End Sequence]))) ++ toASN1 msgSecurityParameter xs
    fromASN1 asn = flip runParseASN1State asn $ do
        Start Sequence <- getNext
        msgId <- getObject
        msgMaxSize <- getObject
        msgFlag <- getObject
        msgSecurityModel <- getObject
        End Sequence <- getNext
        msgSecurityParameter <- getObject
        return $ HeaderData msgId msgMaxSize msgFlag msgSecurityModel msgSecurityParameter


instance ASN1Object MsgID where
    toASN1 (MsgID x) xs = IntVal x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        return $ MsgID x

instance ASN1Object MsgMaxSize where
    toASN1 (MsgMaxSize x) xs = IntVal x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        return $ MsgMaxSize x

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


instance ASN1Object MsgSecurityModel where
    toASN1 UserBasedSecurityModel xs = IntVal 3 : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        case x of
             3 -> return UserBasedSecurityModel
             _ -> error "other security model"

instance Show MsgSecurityParameter where
    show msg = "MsgSecurityParameter:\n\t\tAuthoritiveEngineId: " 
       ++ show (msg ^. msgAuthoritiveEngineId )
       ++ "\n\t\tAuthoritiveEngineBoots: " ++ show (msg ^. msgAuthoritiveEngineBoots )
       ++ "\n\t\tAuthoritiveEngineTime: " ++ show (msg ^. msgAuthoritiveEngineTime )
       ++ "\n\t\tUserName: " ++ show (msg ^. msgUserName )
       ++ "\n\t\tAuthenticationParameters: " ++ show (msg ^. msgAuthenticationParameters )
       ++ "\n\t\tPrivacyParameters: " ++ show (msg ^. msgPrivacyParameters )

instance ASN1Object MsgSecurityParameter where
    toASN1 msg xs = OctetString (encodeASN1' DER
      [ Start Sequence
      ,   OctetString $ msg ^. msgAuthoritiveEngineId 
      ,   IntVal $ msg ^. msgAuthoritiveEngineBoots
      ,   IntVal $ msg ^. msgAuthoritiveEngineTime
      ,   OctetString $ msg ^. msgUserName 
      ,   OctetString $ msg ^. msgAuthenticationParameters
      ,   OctetString $ msg ^. msgPrivacyParameters
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

newtype ContextEngineID = ContextEngineID ByteString deriving (Show, Eq)

deriving instance Monoid ContextEngineID

newtype ContextName = ContextName ByteString deriving (Show, Eq)

deriving instance Monoid ContextName

data ScopedPDU = ScopedPDU 
  { _contextEngineId :: ContextEngineID
  , _contextName :: ContextName
  , _pdu :: PDU 
  } deriving (Eq)

instance Monoid ScopedPDU where
    mempty = ScopedPDU mempty mempty mempty
    mappend (ScopedPDU a0 b0 c0)
            (ScopedPDU a1 b1 c1)
            = ScopedPDU (a0 <> a1) (b0 <> b1) (c0 <> c1)

makeLenses ''ScopedPDU

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

