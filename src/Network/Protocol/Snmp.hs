{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE FlexibleInstances #-}
module Network.Protocol.Snmp (
-- * snmp types
  Value(..)
, OID
, OIDS
-- * top level types
, V2
, V3
, Version(..)
, Packet
-- ** header
, Header 
-- *** header snmpV2
, Community(..)
-- *** header snmpV3
, ID(..)
, MaxSize(..)
, Flag(..)
, SecurityModel(..)
, SecurityParameter(..)
, Reportable
, PrivAuth(..)
-- ** PDU
, PDU
-- *** PDU universal
, Request(..)
, RequestId
, ErrorStatus
, ErrorIndex
, Suite(..)
, Coupla(..)
-- *** PDU snmpV3
, ContextEngineID(..)
, ContextName(..)
-- * pack, unpack Packet
, Pack(..)
-- * some classes and helpers 
-- *** universal, for work with both versions
, HasItem(..)
-- *** v2 only, for work with Header V2
, HasV2(..)
-- *** v3 only, for work with Header V3, PDU V3
, HasV3(..)
-- *** create new Packet
, Construct(..)
-- ** helpers for work with Packet
-- *** universal
, getVersion
, getRequest
, setRequest
, getRid
, setRid
, getSuite
, setSuite
, getErrorStatus
, setErrorStatus
-- *** v2 only
, setCommunityP
-- *** v3 only
, setIDP
, setMaxSizeP
, setReportable
, setPrivAuth
, setUserName
, getAuthenticationParameters
, setAuthenticationParameters
, getEngineId
-- * authentication
, passwordToKey
, signPacket
, AuthType(..)
, PrivType(..)
, Password
, Key
, cleanPass
-- * priv
, testEID
, testPriv
, testSalt
, testBody
, testEID1
, testSalt1
, testBody1
, desEncrypt
, desDecrypt
, encryptPacket
-- , stripBS
-- * exceptions
, ClientException(..) 
-- * usage example
-- $example
)
where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Word (Word8, Word32)
import Data.Bits (testBit, complement, shiftL, (.|.), (.&.), setBit, shiftR, zeroBits, xor, clearBit)
import Data.ASN1.Types (ASN1Object(..), ASN1(..), OID, ASN1ConstructionType(..), ASN1Class(..))
import Data.ASN1.Parse (getNext, getObject, runParseASN1, runParseASN1State, ParseASN1(..), getNextContainer, onNextContainer, getMany)
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding (encodeASN1', decodeASN1')
import Control.Applicative ((<$>), (<*>), (*>), (<*))
import Data.Monoid (Monoid, (<>))
import Control.Exception (Exception)
import Data.Typeable (Typeable)
import qualified Crypto.Hash.MD5 as Md5
import qualified Crypto.Hash.SHA1 as Sha
import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.Cipher.Types as Priv
import qualified Crypto.Cipher.DES as Priv
import Data.IORef (newIORef, IORef, readIORef, atomicWriteIORef)
import Debug.Trace (trace)

-- $example
--
-- Here example for snmpV2 
--
-- @
-- import Network.Protocol.Snmp
-- import Control.Applicative
-- import Network.Socket.ByteString (recv, sendAll)
-- import Network.Socket hiding (recv, sendAll)
--
-- -- create new empty packet
-- v2 :: Packet
-- v2 = initial Version2
-- 
-- community = Community "hello"
--
-- oi = Coupla [1,3,6,1,2,1,1,4,0] Zero
--
-- -- set community, oid
-- packet :: Community -> Coupla -> Packet
-- packet community oi = 
--   setCommunityP community . setSuite (Suite [oi]) $ v2
-- 
-- -- here must be code for create udp socket
-- makeSocket :: Hostname -> Port -> IO Socket
-- makeSocket = undefined
--
-- main :: IO ()
-- main = do
--    socket <- makeSocket "localhost" "161"
--    sendAll socket $ encode $ setRequest (GetRequest 1 0 0) packet
--    result <- decode <$\> recv socket 1500 :: IO Packet
--    print $ getSuite result 
-- 
-- @
-- 

-----------------------------------------------------------------------------------------------------------------

-- | Phantom type for version 2 (Header V2, PDU V2)
data V2
-- | Phantom type for version 3 (Header V3, PDU V3)
data V3

-- | Snmp version tag
data Version = Version1
             | Version2 
             | Version3
             deriving (Eq, Show)

type OIDS = [OID]

-- | Top level type, which describe snmp packet
data Packet where
  V2Packet :: Version -> Header V2 -> PDU V2 -> Packet
  V3Packet :: Version -> Header V3 -> PDU V3 -> Packet

deriving instance Show Packet 
deriving instance Eq Packet 

-- | Snmp header without version tag
data Header a where
  V2Header :: Community -> Header V2
  V3Header :: ID -> MaxSize -> Flag -> SecurityModel -> SecurityParameter -> Header V3

deriving instance Show (Header a)
deriving instance Eq (Header a)

-- | Snmp body
data PDU a where
  PDU :: Request -> Suite -> PDU V2
  ScopedPDU :: ContextEngineID -> ContextName -> PDU V2 -> PDU V3
  CryptedPDU :: ByteString -> PDU V3

deriving instance Show (PDU a)
deriving instance Eq (PDU a)

-- | Snmp data types
data Value = Simple ASN1
           | Zero
           | Integer Integer
           | String ByteString
           | IpAddress Word8 Word8 Word8 Word8
           | Counter32 Integer
           | Gaude32 Integer
           | TimeTicks Integer
           | Opaque ByteString
           | Counter64 Integer
           | ZeroDotZero
           | NoSuchInstance
           | NoSuchObject
           | EndOfMibView
           deriving (Show, Eq)

-- | Request id 
type RequestId = Integer

-- | Error status 
type ErrorStatus = Integer

-- | Error index 
type ErrorIndex = Integer

-- | requests
data Request = GetRequest     { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | GetNextRequest { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | GetResponse    { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | SetRequest     { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | GetBulk        { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | Inform         { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | V2Trap         { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | Report         { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             deriving (Show, Eq)

-- | Coupla oid -> value
data Coupla = Coupla { _oid :: OID, _value :: Value } deriving (Eq)

-- | Variable bindings
newtype Suite = Suite [Coupla] deriving (Eq, Monoid)

-- ** Types describing header

-- | (snmp2 only) Community for 2(1) version
newtype Community = Community ByteString deriving (Show, Eq)

-- | (snmp3 only) Message Identifier (like RequestId in PDU)
newtype ID = ID Integer deriving (Show, Eq)

-- | (snmp3 only) Message max size must be > 484
newtype MaxSize = MaxSize Integer deriving (Show, Eq)

-- | (snmp3 only) rfc3412, type for create message flag
data PrivAuth = NoAuthNoPriv | AuthNoPriv | AuthPriv deriving (Show, Eq)

-- | (snmp3 only) rfc3412, as PrivAuth
type Reportable = Bool

-- | (snmp3 only) rfc3412, message flag
data Flag = Flag Reportable PrivAuth  deriving (Show, Eq)

-- | (snmp3 only) rfc3412, security model
data SecurityModel = UserBasedSecurityModel deriving (Show, Eq)

-- | (snmp3 only) rfc3412, security parameter
data SecurityParameter = SecurityParameter 
  { authoritiveEngineId :: ByteString
  , authoritiveEngineBoots :: Integer
  , authoritiveEngineTime :: Integer
  , userName :: ByteString
  , authenticationParameters :: ByteString
  , privacyParameters :: ByteString
  }
  deriving (Eq)

-- | (snmp3 only) rfc3412, types for ScopedPDU
newtype ContextEngineID = ContextEngineID ByteString deriving (Show, Eq)
newtype ContextName = ContextName ByteString deriving (Show, Eq)

-- | some exception
data ClientException = TimeoutException 
                     | ServerException Integer
                     deriving (Typeable, Eq)

-- | class for make binary packet from [ASN1] 
class Pack a where
    encode :: a -> ByteString
    decode :: ByteString -> a

-- | some universal getters, setters
class HasItem a where
    getHeader :: Packet -> Header a
    setHeader :: Header a -> Packet -> Packet
    getPDU :: Packet -> PDU a
    setPDU :: PDU a -> Packet -> Packet

-- | (snmp2 only) getters, setters for work with Header V2
class HasV2 a where
    getCommunity :: Header a -> Community
    setCommunity :: Community -> Header a -> Header a

-- | (snmp3 only) getters, setters for work with Header V3 and PDU V3.
class HasV3 a where
    getID :: Header a -> ID
    getMaxSize :: Header a -> MaxSize
    getFlag :: Header a -> Flag
    getSecurityModel :: Header a -> SecurityModel
    getSecurityParameter :: Header a -> SecurityParameter
    getContextEngineID :: PDU a -> ContextEngineID
    getContextName :: PDU a -> ContextName
    setID :: ID -> Header a -> Header a
    setMaxSize :: MaxSize -> Header a -> Header a
    setFlag :: Flag -> Header a -> Header a
    setSecurityModel :: SecurityModel -> Header a -> Header a
    setSecurityParameter :: SecurityParameter -> Header a -> Header a
    setContextEngineID :: ContextEngineID -> PDU a -> PDU a
    setContextName :: ContextName -> PDU a -> PDU a

-- | initial new object, like mempty for monoid
class Construct a where
    initial :: a

----------------------------------------------------------------------------------------
instance Construct (Version -> Packet) where
    initial Version3 = V3Packet Version3 initial initial
    initial Version2 = V2Packet Version2 initial initial

instance Construct (Header V3) where
    initial = V3Header (ID 0) (MaxSize 65007) (Flag False NoAuthNoPriv) UserBasedSecurityModel initial

instance Construct (Header V2) where
    initial = V2Header (Community "")

instance Construct (PDU V3) where
    initial = ScopedPDU (ContextEngineID "") (ContextName "") initial

instance Construct (PDU V2) where
    initial = PDU initial initial

instance Construct SecurityParameter where
    initial = SecurityParameter "" 0 0 "" "" ""

instance Construct Suite where
    initial = Suite []

instance Construct Request where
     initial = GetRequest 0 0 0
----------------------------------------------------------------------------------------
instance HasItem V2 where
    getHeader (V2Packet _ x _) = x
    setHeader h (V2Packet v _ x) = V2Packet v h x
    getPDU (V2Packet _ _ x) = x
    setPDU p (V2Packet v h _) = V2Packet v h p

instance HasItem V3 where
    getHeader (V3Packet _ x _) = x
    setHeader h (V3Packet v _ x) = V3Packet v h x
    getPDU (V3Packet _ _ x) = x
    setPDU p (V3Packet v h _) = V3Packet v h p

instance HasV2 V2 where
    getCommunity (V2Header c) = c
    setCommunity c (V2Header _) = V2Header c

instance HasV3 V3 where
    getID (V3Header i _ _ _ _) = i
    getMaxSize (V3Header _ i _ _ _) = i
    getFlag (V3Header _ _ i _ _) = i
    getSecurityModel (V3Header _ _ _ i _) = i
    getSecurityParameter (V3Header _ _ _ _ i) = i
    getContextEngineID (ScopedPDU i _ _) = i
    getContextName (ScopedPDU _ i _) = i
    setID i (V3Header _ a b c d) = V3Header i a b c d
    setMaxSize i (V3Header a _ b c d) = V3Header a i b c d
    setFlag i (V3Header a b _ c d) = V3Header a b i c d
    setSecurityModel i (V3Header a b c _ d) = V3Header a b c i d
    setSecurityParameter i (V3Header a b c d _) = V3Header a b c d i
    setContextEngineID i (ScopedPDU _ b c) = ScopedPDU i b c
    setContextName i (ScopedPDU a _ b) = ScopedPDU a i b 

----------------------------------------------------------------------------------------
setIDP :: ID -> Packet -> Packet 
setIDP x p = 
  let header = getHeader p :: Header V3
      newHeader = setID x header
  in setHeader newHeader p

setMaxSizeP :: MaxSize -> Packet -> Packet 
setMaxSizeP x p = 
  let header = getHeader p :: Header V3
      newHeader = setMaxSize x header
  in setHeader newHeader p 

setCommunityP :: Community -> Packet -> Packet 
setCommunityP x p = 
  let header = getHeader p :: Header V2
      newHeader = setCommunity x header
  in setHeader newHeader p

getEngineId :: Packet -> EngineId
getEngineId p = 
  let header = getHeader p :: Header V3
      sp = getSecurityParameter header
  in authoritiveEngineId sp


setReportable :: Reportable -> Packet -> Packet
setReportable r p = 
  let header = getHeader p :: Header V3
      Flag _ a = getFlag header
      newHeader = setFlag (Flag r a) header
  in setHeader newHeader p

setPrivAuth :: PrivAuth -> Packet -> Packet
setPrivAuth x p = 
  let header = getHeader p :: Header V3
      Flag r _ = getFlag header
      newHeader = setFlag (Flag r x) header
  in setHeader newHeader p

setUserName :: ByteString -> Packet -> Packet 
setUserName x p = 
  let header = getHeader p :: Header V3
      sp = getSecurityParameter header
      newHeader = setSecurityParameter (sp { userName = x }) header
  in setHeader newHeader p

setAuthenticationParameters :: ByteString -> Packet -> Packet 
setAuthenticationParameters x p = 
  let header = getHeader p :: Header V3
      sp = getSecurityParameter header
      newHeader = setSecurityParameter (sp { authenticationParameters = x }) header
  in setHeader newHeader p
  
getAuthenticationParameters :: Packet -> ByteString
getAuthenticationParameters p = 
  let header = getHeader p :: Header V3
  in authenticationParameters (getSecurityParameter header)

setPrivParameters :: ByteString -> Packet -> Packet 
setPrivParameters x p = 
  let header = getHeader p :: Header V3
      sp = getSecurityParameter header
      newHeader = setSecurityParameter (sp { privacyParameters = x }) header
  in setHeader newHeader p


getVersion :: Packet -> Version
getVersion (V2Packet v _ _) = v
getVersion (V3Packet v _ _) = v

getRid :: Packet -> RequestId 
getRid (V2Packet _ _ (PDU r _)) = rid r 
getRid (V3Packet _ _ (ScopedPDU _ _ (PDU r _))) = rid r 

setRid :: RequestId -> Packet -> Packet
setRid r (V2Packet v h (PDU req s)) = V2Packet v h (PDU req { rid = r } s)
setRid r (V3Packet v h (ScopedPDU a b (PDU req s))) = V3Packet v h (ScopedPDU a b (PDU req { rid = r } s))

getErrorStatus :: Packet -> ErrorStatus 
getErrorStatus (V2Packet _ _ (PDU r _)) = es r 
getErrorStatus (V3Packet _ _ (ScopedPDU _ _ (PDU r _))) = es r 

setErrorStatus :: ErrorStatus -> Packet -> Packet
setErrorStatus e (V2Packet v h (PDU req s)) = V2Packet v h (PDU req { es = e } s)
setErrorStatus e (V3Packet v h (ScopedPDU a b (PDU req s))) = V3Packet v h (ScopedPDU a b (PDU req { es = e } s))

getSuite :: Packet -> Suite
getSuite (V2Packet _ _ (PDU _ r)) = r 
getSuite (V3Packet _ _ (ScopedPDU _ _ (PDU _ r))) = r 

setSuite :: Suite -> Packet -> Packet
setSuite s (V2Packet v h (PDU req _)) = V2Packet v h (PDU req s)
setSuite s (V3Packet v h (ScopedPDU a b (PDU req _))) = V3Packet v h (ScopedPDU a b (PDU req s))

getRequest :: Packet -> Request
getRequest (V2Packet _ _ (PDU r _)) = r 
getRequest (V3Packet _ _ (ScopedPDU _ _ (PDU r _))) = r 

setRequest :: Request -> Packet -> Packet
setRequest req (V2Packet v h (PDU _ s)) = V2Packet v h (PDU req s)
setRequest req (V3Packet v h (ScopedPDU a b (PDU _ s))) = V3Packet v h (ScopedPDU a b (PDU req s))
----------------------------------------------------------------------------------------

instance ASN1Object (Header V2) where
    toASN1 (V2Header c) xs = toASN1 c xs 
    fromASN1 asn = flip runParseASN1State asn $ V2Header <$> getObject

sS = do
    Start Sequence <- getNext
    return ()

eS = do
    End Sequence <- getNext
    return ()

instance ASN1Object (Header V3) where
    toASN1 (V3Header i ms f sm sp) xs = 
        Start Sequence : toASN1 i (toASN1 ms (toASN1 f (toASN1 sm [End Sequence]))) ++ toASN1 sp xs
    fromASN1 asn = flip runParseASN1State asn $
        V3Header <$> (sS *> getObject) <*> getObject <*> getObject <*> (getObject <* eS) <*> getObject

instance ASN1Object (PDU V2) where
    toASN1 (PDU (GetRequest rid _ _    ) sd) xs = (Start $ Container Context 0):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 0)] ++ xs
    toASN1 (PDU (GetNextRequest rid _ _) sd) xs = (Start $ Container Context 1):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 1)] ++ xs
    toASN1 (PDU (GetResponse rid es ei ) sd) xs = (Start $ Container Context 2):IntVal rid : IntVal es : IntVal ei: Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 2)] ++ xs
    toASN1 (PDU (SetRequest rid _ _    ) sd) xs = (Start $ Container Context 3):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 3)] ++ xs
    toASN1 (PDU (GetBulk rid es ei     ) sd) xs = (Start $ Container Context 5):IntVal rid : IntVal es : IntVal ei: Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 4)] ++ xs
    toASN1 (PDU (Report rid es ei      ) sd) xs = (Start $ Container Context 8):IntVal rid : IntVal es : IntVal ei: Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 8)] ++ xs
    fromASN1 asn = flip runParseASN1State asn pduParser

pduParser :: ParseASN1 (PDU V2)
pduParser = do
    Start (Container Context n) <- getNext
    IntVal rid <- getNext
    IntVal es <- getNext
    IntVal ei <- getNext
    x <- getNextContainer Sequence 
    End (Container Context _) <- getNext
    let psuite = fromASN1 x
    case (n, psuite) of
         (0, Right (suite, _)) -> return $ PDU (GetRequest     rid es ei) suite
         (1, Right (suite, _)) -> return $ PDU (GetNextRequest rid es ei) suite
         (2, Right (suite, _)) -> return $ PDU (GetResponse    rid es ei) suite
         (3, Right (suite, _)) -> return $ PDU (SetRequest     rid es ei) suite
         (5, Right (suite, _)) -> return $ PDU (GetBulk        rid es ei) suite
         (8, Right (suite, _)) -> return $ PDU (Report         rid es ei) suite
         e -> error $ "cant parse PDU " ++ show e

instance ASN1Object (PDU V3) where
    toASN1 (ScopedPDU (ContextEngineID x) (ContextName y) pdu) xs = 
      [Start Sequence, OctetString x, OctetString y] ++ (toASN1 pdu (End Sequence :xs))
    toASN1 (CryptedPDU cryptedBody) xs = OctetString cryptedBody : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        whatIs <- getNext
        case whatIs of
             Start Sequence -> do
                 OctetString x <- getNext
                 OctetString y <- getNext
                 p <- pduParser 
                 End Sequence <- getNext
                 return $ ScopedPDU (ContextEngineID x) (ContextName y) p
             OctetString x -> return $ CryptedPDU x

instance ASN1Object Version where
    toASN1 Version1 xs = IntVal 0 : xs
    toASN1 Version2 xs = IntVal 1 : xs
    toASN1 Version3 xs = IntVal 3 : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        case x of 
             0 -> return Version1
             1 -> return Version2
             3 -> return Version3

instance ASN1Object Packet where
    toASN1 (V2Packet Version2 header body) _ = Start Sequence : toASN1 Version2 (toASN1 header (toASN1 body [End Sequence]))
    toASN1 (V3Packet Version3 header body) _ = Start Sequence : toASN1 Version3 (toASN1 header (toASN1 body [End Sequence]))
    fromASN1 asn = flip runParseASN1State asn $ onNextContainer Sequence $ do
        v <- getObject
        case v of
             Version2 -> V2Packet Version2 <$> getObject <*> getObject
             Version3 -> V3Packet Version3 <$> getObject <*> getObject

instance ASN1Object Value where
    toASN1 NoSuchObject xs = Other Context 0 "" : xs
    toASN1 NoSuchInstance xs = Other Context 1 "" : xs
    toASN1 EndOfMibView xs = Other Context 2 "" : xs
    toASN1 (Simple x) xs = x : xs
    toASN1 Zero xs = Null : xs
    toASN1 ZeroDotZero xs = OID [0,0] : xs
    toASN1 (Integer x) xs = IntVal x : xs
    toASN1 (String x) xs = OctetString x : xs
    toASN1 (IpAddress a1 a2 a3 a4) xs = Other Application 0 (B.pack [a1, a2, a3, a4]) : xs
    toASN1 (Counter32 x) xs = Other Application 1 (packInteger x) : xs
    toASN1 (Gaude32 x) xs = Other Application 2 (packInteger x) : xs
    toASN1 (TimeTicks x) xs = Other Application 3 (packInteger x) : xs
    toASN1 (Opaque x) xs = Other Application 4 x : xs
    toASN1 (Counter64 x) xs = Other Application 6 (packInteger x) : xs
    fromASN1 asn = flip runParseASN1State asn (unp =<< getNext)
      where
      unp (Other Context 0 "") = return NoSuchObject
      unp (Other Context 1 "") = return NoSuchInstance
      unp (Other Context 2 "") = return EndOfMibView
      unp Null = return Zero
      unp (OID [0,0]) = return ZeroDotZero
      unp (IntVal x) = return $ Integer x
      unp (OctetString x) = return $ String x
      unp (Other Application 0 y) = let [a1, a2, a3, a4] = B.unpack y
                                    in return $ IpAddress a1 a2 a3 a4
      unp (Other Application 1 y) = case (unpackInteger y) of
                                         Right z -> return $ Counter32 z
                                         Left e -> error e
      unp (Other Application 2 y) = case (unpackInteger y) of
                                         Right z -> return $ Gaude32 z
                                         Left e -> error e
      unp (Other Application 3 y) = case (unpackInteger y) of
                                         Right z -> return $ TimeTicks z
                                         Left e -> error e
      unp (Other Application 4 y) = return $ Opaque y
      unp (Other Application 6 y) = case (unpackInteger y) of
                                         Right z -> return $ Counter64 z
                                         Left e -> error e
      unp x = return . Simple $ x

instance ASN1Object Community where
    toASN1 (Community x) xs = OctetString x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        OctetString x <- getNext
        return $ Community x

instance Show SecurityParameter where
    show msg = "SecurityParameter:\n\t\tAuthoritiveEngineId: " 
       ++ show (authoritiveEngineId msg )
       ++ "\n\t\tAuthoritiveEngineBoots: " ++ show (authoritiveEngineBoots msg )
       ++ "\n\t\tAuthoritiveEngineTime: " ++ show (authoritiveEngineTime msg )
       ++ "\n\t\tUserName: " ++ show (userName msg )
       ++ "\n\t\tAuthenticationParameters: " ++ show (authenticationParameters msg )
       ++ "\n\t\tPrivacyParameters: " ++ show (privacyParameters msg )

instance ASN1Object ID where
    toASN1 (ID x) xs = IntVal x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        return $ ID x

instance ASN1Object MaxSize where
    toASN1 (MaxSize x) xs = IntVal x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        return $ MaxSize x

instance ASN1Object Flag where
    toASN1 (Flag r pa) xs = let zero = zeroBits :: Word8
                                reportable = if r then setBit zero 0 else zero
                                privauth = case pa of
                                                NoAuthNoPriv -> zero
                                                AuthNoPriv -> setBit zero 2
                                                AuthPriv -> setBit zero 1 .|. setBit zero 2
                                flag = reportable .|. privauth
                            in OctetString (B.pack [flag]) : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        OctetString x <- getNext
        let [w] = B.unpack x
        trace (show w) return $ case (testBit w 0, testBit w 1) of
                      (True, True) -> Flag (testBit w 2) AuthPriv
                      (False, False) -> Flag (testBit w 2) NoAuthNoPriv
                      (True, False) -> Flag (testBit w 2) AuthNoPriv
                      _ -> error "bad flag"


instance ASN1Object SecurityModel where
    toASN1 UserBasedSecurityModel xs = IntVal 3 : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        case x of
             3 -> return UserBasedSecurityModel
             _ -> error "other security model"

instance ASN1Object SecurityParameter where
    toASN1 SecurityParameter{..} xs = OctetString (encodeASN1' DER
      [ Start Sequence
      ,   OctetString authoritiveEngineId 
      ,   IntVal authoritiveEngineBoots 
      ,   IntVal authoritiveEngineTime 
      ,   OctetString userName 
      ,   OctetString authenticationParameters 
      ,   OctetString privacyParameters 
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

parseMsgSecurityParameter :: [ASN1] -> Either String SecurityParameter
parseMsgSecurityParameter asn = flip runParseASN1 asn $ do
     Start Sequence <- getNext
     OctetString msgAuthoritiveEngineId <- getNext
     IntVal msgAuthoritiveEngineBoots <- getNext
     IntVal msgAuthoritiveEngineTime <- getNext
     OctetString msgUserName <- getNext
     OctetString msgAuthenticationParameters <- getNext
     OctetString msgPrivacyParameters <- getNext
     End Sequence <- getNext
     return $ SecurityParameter msgAuthoritiveEngineId msgAuthoritiveEngineBoots msgAuthoritiveEngineTime msgUserName msgAuthenticationParameters msgPrivacyParameters 

instance Pack Packet where
    encode s = encodeASN1' DER $ toASN1 s []
    decode = toB 

toB :: ByteString -> Packet 
toB bs = let a = fromASN1 <$> decodeASN1' DER bs
         in case a of
                 Right (Right (r, _)) -> r
                 _ -> error "bad packet"
                 --}
                 --
instance Show Coupla where
    show (Coupla o v) = oidToString o ++ " = " ++ show v

instance Show Suite where
    show (Suite xs) = unlines $ map show xs

oidToString :: OID -> String
oidToString xs = foldr1 (\x y -> x ++ "." ++ y) $ map show xs

instance ASN1Object Suite where
    toASN1 (Suite xs) ys = foldr toA [] xs ++ ys
      where 
      toA ::Coupla -> [ASN1] -> [ASN1]
      toA (Coupla o v) zs = [Start Sequence , OID o] ++ toASN1 v (End Sequence : zs)
    fromASN1 asn = flip runParseASN1State asn $ do
        xs <- getMany $ do
               Start Sequence <- getNext
               OID x <- getNext
               v <-  getObject
               End Sequence <- getNext
               return $ Coupla x v
        return $ Suite xs

instance Show ClientException where
    show TimeoutException = "Timeout exception"
    show (ServerException 1) = "tooBig"
    show (ServerException 2) = "noSuchName"
    show (ServerException 3) = "badValue"
    show (ServerException 4) = "readOnly"
    show (ServerException 5) = "genErr"
    show (ServerException 6) = "noAccess"
    show (ServerException 7) = "wrongType"
    show (ServerException 8) = "wrongLength"
    show (ServerException 9) = "wrongEncoding"
    show (ServerException 10) = "wrongValue"
    show (ServerException 11) = "noCreation"
    show (ServerException 12) = "inconsistentValue"
    show (ServerException 13) = "resourceUnavailable"
    show (ServerException 14) = "commitFailed"
    show (ServerException 15) = "undoFailed"
    show (ServerException 16) = "authorizationError"
    show (ServerException 17) = "notWritable"
    show (ServerException 18) = "inconsistentName"
    show (ServerException 80) = "General IO failure occured on the set request"
    show (ServerException 81) = "General SNMP timeout occured"
    show (ServerException x) = "Exception " ++ show x

instance Exception ClientException

-- copy paste from asn1-encoding

packInteger :: Integer -> ByteString
packInteger = B.pack . bytesOfInt 

unpackInteger :: ByteString -> Either String Integer
unpackInteger = getIntegerRaw "Integer"

bytesOfInt :: Integer -> [Word8]
bytesOfInt i
  | i > 0      = if testBit (head uints) 7 then 0 : uints else uints
  | i == 0     = [0]
  | otherwise  = if testBit (head nints) 7 then nints else 0xff : nints
      where
      uints = bytesOfUInt (abs i)
      nints = reverse $ plusOne $ reverse $ map complement $ uints
      plusOne []     = [1]
      plusOne (x:xs) = if x == 0xff then 0 : plusOne xs else (x+1) : xs


--bytesOfUInt i = B.unfoldr (\x -> if x == 0 then Nothing else Just (fromIntegral (x .&. 0xff), x `shiftR` 8)) i
bytesOfUInt :: Integer -> [Word8]
bytesOfUInt x = reverse (list x)
  where list i = if i <= 0xff then [fromIntegral i] else (fromIntegral i .&. 0xff) : list (i `shiftR` 8)

{- | According to X.690 section 8.4 integer and enumerated values should be encoded the same way. -}
getIntegerRaw :: String -> ByteString -> Either String Integer
getIntegerRaw typestr s
    | B.length s == 0 = Left $ typestr ++ ": null encoding"
    | B.length s == 1 = Right $ snd $ intOfBytes s
    | otherwise       =
        if (v1 == 0xff && testBit v2 7) || (v1 == 0x0 && (not $ testBit v2 7))
            then Left $ typestr ++ ": not shortest encoding"
            else Right $ snd $ intOfBytes s
    where
        v1 = s `B.index` 0
        v2 = s `B.index` 1

{- | intOfBytes returns the number of bytes in the list and
the represented integer by a two's completement list of bytes -}
intOfBytes :: ByteString -> (Int, Integer)
intOfBytes b
    | B.length b == 0   = (0, 0)
    | otherwise         = (len, if isNeg then -(maxIntLen - v + 1) else v)
    where
        (len, v)  = uintOfBytes b
        maxIntLen = 2 ^ (8 * len) - 1
        isNeg     = testBit (B.head b) 7

{- | uintOfBytes returns the number of bytes and the unsigned integer represented by the bytes -}
uintOfBytes :: ByteString -> (Int, Integer)
uintOfBytes b = (B.length b, B.foldl (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0 b)

------------------------------------------------------------------------------------------------------

cleanPass = B.pack $ replicate 12 0x00
 
data PrivType = DES | AES deriving (Show, Eq)
data AuthType = MD5 | SHA deriving (Show, Eq)
type Key = ByteString
type Password = ByteString

hash :: AuthType -> (ByteString -> ByteString)
hash MD5 = Md5.hash
hash SHA = Sha.hash

hashlazy :: AuthType -> (BL.ByteString -> ByteString)
hashlazy MD5 = Md5.hashlazy
hashlazy SHA = Sha.hashlazy

-- | (only V3) sign Packet 
signPacket :: AuthType -> Key -> Packet -> Packet 
signPacket at key packet = 
    let packetAsBin = encode packet
        sign = B.take 12 $ HMAC.hmac (hash at) 64 key packetAsBin 
    in setAuthenticationParameters sign packet

-- | create auth key from password and context engine id
passwordToKey :: AuthType -> Password -> EngineId -> Key
passwordToKey at pass eid = 
  let buf = BL.take 1048576 $ BL.fromChunks $ repeat pass
      authKey = hashlazy at buf
  in hash at $ authKey <> eid <> authKey

-----------------------------------------------------------------------------------------------------

type EngineBootId = Integer
type PrivacyParameter = ByteString
type EngineId = ByteString

pk :: ByteString
pk = "helloallhelloall"
eb :: Integer
eb = 40

testEID :: ByteString
testEID = "\128\NUL\US\136\128v\224\131\SI|\155\SUBT\NUL\NUL\NUL\NUL"

testEID1 :: ByteString
testEID1 = "\128\NUL\US\136\128P\247.l\SO\203\GST\NUL\NUL\NUL\NUL"

testPriv :: ByteString
testPriv = "helloall"

testSalt :: ByteString
testSalt = "\NUL\NUL\NUL\SOH<\175\244\201"

testBody :: ByteString
testBody = "w\175\166{\142,\144s\248\b\252t\FS\229I\152\EM\f\193F0\ETX\207\SYN\193\155i\177\190\213J\239\128\154<\128{\a\194\255Y8\155+\194\161\ESCM\191\184\161%v\184\220\145"

testSalt1 :: ByteString
testSalt1 = "\NUL\NUL\NUL\ETB\243\137\129\156"

testBody1 :: ByteString
testBody1 = "\237;x;wT\208\230\199\178\STX\DLE\ENQ\166\150\193\240\184\151\EOT\NAKj\215E\195\229\219\n\192\166\153\184\215\209\205k\163Y0\170\146C\206\206\EOT\236\SI\193\184X.\234\131\133\241\DLE*\129\204\179.\188\141\197"

encryptPacket :: PrivType -> Key -> Packet -> Packet
encryptPacket DES key packet = 
    let eib = authoritiveEngineBoots $ getSecurityParameter $ (getHeader packet :: Header V3)
        body = encodeASN1' DER $ toASN1 (getPDU packet :: PDU V3) []
        encrypted = desEncrypt key eib body 
    in setPrivParameters (B.take 8 key) . setPDU (CryptedPDU encrypted) $ packet
encryptPacket _ _ _ = error "not implement"

desEncrypt :: Key -> EngineBootId -> ByteString -> ByteString
desEncrypt privKey engineBoot dataToEncrypt = 
    let desKey = B.take 8 privKey
        preIV = B.drop 8 $ B.take 16 privKey
        localInt = 100
        eB = fromIntegral engineBoot
        salt  = [ (shiftR eB 24 .&. 0xff) :: Word8
                , shiftR eB 16 .&. 0xff
                , shiftR eB 8  .&. 0xff
                , shiftR eB 0  .&. 0xff
                , (shiftR localInt 24   .&. 0xff) :: Word8
                , shiftR localInt 16   .&. 0xff
                , shiftR localInt  8   .&. 0xff
                , shiftR localInt  0   .&. 0xff
                ] 
        ivR = map (uncurry xor) $ zip (B.unpack preIV) salt
        Just iv = Priv.makeIV (B.pack ivR)
        Right key = Priv.makeKey desKey 
        des = Priv.cipherInit key :: Priv.DES
    in Priv.cbcEncrypt des iv dataToEncrypt
        
desDecrypt :: Key -> PrivacyParameter -> ByteString -> ByteString
desDecrypt privKey privParameters dataToDecrypt =
    let desKey = B.take 8 privKey
        preIV = B.drop 8 $ B.take 16 privKey
        salt = privParameters
        ivR = map (uncurry xor) $ zip (B.unpack preIV) (B.unpack salt)
        Just iv = Priv.makeIV (B.pack ivR)
        Right key = Priv.makeKey desKey
        des = Priv.cipherInit key :: Priv.DES
    in stripBS $ Priv.cbcDecrypt des iv dataToDecrypt


stripBS :: ByteString -> ByteString
stripBS bs = 
    let bs' = B.drop 1 bs
        l1 = fromIntegral $ B.head bs'
    in if testBit l1 7
        then case clearBit l1 7 of
                  0   -> undefined
                  len -> 
                    let size = uintbs (B.take len (B.drop 1 bs'))
                    in B.take (size + len + 2) bs
        else B.take (l1 + 2) bs
    where
      {- uintbs return the unsigned int represented by the bytes -}
      uintbs = B.foldl (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0
