{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE StandaloneDeriving         #-}
module Network.Protocol.Snmp
    (
    -- * snmp types
      Oid(..)
    , Value(..)
    -- * top level types
    , V2
    , V3
    , Version(..)
    , Packet(..)
    -- ** header
    , Header(..)
    -- *** header snmpV2
    , Community(..)
    -- *** header snmpV3
    , ID(..)
    , MaxSize(..)
    , Flag(..)
    , ErrorIndex(..)
    , ErrorStatus(..)
    , RequestId(..)
    , SecurityModel(..)
    , SecurityParameter(..)
    , Reportable
    , PrivAuth(..)
    , EngineBootId
    , PrivacyParameter
    , EngineTime
    , EngineId
    -- ** PDU
    , PDU (..)
    -- *** PDU universal
    , Request(..)
    , Suite(..)
    , Coupla(..)
    -- *** PDU snmpV3
    , ContextEngineID(..)
    , ContextName(..)
    -- * some classes and helpers
    -- *** universal, for work with both versions
    , HasItem(..)
    -- *** v2 only, for work with Header V2
    , getCommunity
    , setCommunity
    -- *** v3 only, for work with Header V3, PDU V3
    , getID
    , getMaxSize
    , getFlag
    , getSecurityModel
    , getSecurityParameter
    , getAuthoritiveEngineId
    , getAuthoritiveEngineBoots
    , getAuthoritiveEngineTime
    , getUserName
    , getAuthenticationParameters
    , getPrivacyParameters
    , getContextEngineID
    , getContextName
    , setID
    , setMaxSize
    , setFlag
    , setSecurityModel
    , setSecurityParameter
    , setAuthoritiveEngineId
    , setAuthoritiveEngineBoots
    , setAuthoritiveEngineTime
    , setUserName
    , setAuthenticationParameters
    , setPrivacyParameters
    , setContextEngineID
    , setContextName
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
    , setUserNameP
    , getAuthenticationParametersP
    , setAuthenticationParametersP
    , setReportableP
    , setPrivAuthP
    , getEngineIdP
    , setEngineIdP
    , getEngineBootsP
    , setEngineBootsP
    , getEngineTimeP
    , setEngineTimeP
    , getPrivParametersP
    , setPrivParametersP
    -- * authentication
    , passwordToKey
    , signPacket
    , AuthType(..)
    , PrivType(..)
    , Password(..)
    , Key(..)
    , cleanPass
    -- * priv
    , Salt
    , Raw
    , Encrypted
    , Rand32
    , Rand64
    , desEncrypt
    , desDecrypt
    , aesEncrypt
    , aesDecrypt
    , toSalt
    -- * exceptions
    , SnmpException(..)
    -- * usage example
    -- $example
    ) where

import           Control.Exception    (Exception, throw)
import           Control.Monad
import qualified Crypto.Cipher.AES    as Priv
import qualified Crypto.Cipher.DES    as Priv
import qualified Crypto.Cipher.Types  as Priv
import qualified Crypto.Error         as Priv
import qualified Crypto.Hash          as Hash
import qualified Crypto.MAC.HMAC      as HMAC
import           Data.Bits
import qualified Data.ByteArray       as BA
import           Data.ByteString      (ByteString)
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as BL
import           Data.List            (sort, unfoldr)
import           Data.Monoid          ((<>))
import           Data.Serialize
import           Data.Typeable        (Typeable)
import           Data.Word
import           GHC.Int              (Int32, Int64)

newtype Oid = Oid [Word16]
  deriving (Eq, Ord, Show)

data Value
    = Integer {-# UNPACK #-} !Int32
    | BitString !ByteString
    | OctetString !ByteString
    | Null
    | OI !Oid
    | IpAddress {-# UNPACK #-} !Word8
                {-# UNPACK #-} !Word8
                {-# UNPACK #-} !Word8
                {-# UNPACK #-} !Word8
    | Counter32 {-# UNPACK #-} !Word32
    | Gauge32 {-# UNPACK #-} !Word32
    | TimeTicks {-# UNPACK #-} !Word32
    | Opaque !ByteString
    | NsapAddress !ByteString
    | Counter64 {-# UNPACK #-} !Word64
    | UInteger32 {-# UNPACK #-} !Word32
    | NoSuchObject
    | NoSuchInstance
    | EndOfMibView
  deriving (Eq, Ord, Show)

-- | Phantom type for version 2 (Header V2, PDU V2)
data V2
-- | Phantom type for version 3 (Header V3, PDU V3)
data V3

-- | Snmp version tag
data Version = Version1
             | Version2
             | Version3
  deriving (Eq, Show)

-- | Top level type, which describe snmp packet
data Packet where
    V2Packet :: Version -> Header V2 -> PDU V2 -> Packet
    V3Packet :: Version -> Header V3 -> PDU V3 -> Packet
  deriving (Eq, Show)

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

-- | Request id
newtype RequestId = RequestId Int32 deriving (Show, Eq, Ord)

-- | Error status
newtype ErrorStatus = ErrorStatus Int32 deriving (Show, Eq, Ord)

-- | Error index
newtype ErrorIndex = ErrorIndex Int32 deriving (Show, Eq, Ord)

-- | requests
data Request
    = GetRequest     { rid :: {-# UNPACK #-} !RequestId, es :: {-# UNPACK #-} !ErrorStatus, ei :: {-# UNPACK #-} !ErrorIndex }
    | GetNextRequest { rid :: {-# UNPACK #-} !RequestId, es :: {-# UNPACK #-} !ErrorStatus, ei :: {-# UNPACK #-} !ErrorIndex }
    | GetResponse    { rid :: {-# UNPACK #-} !RequestId, es :: {-# UNPACK #-} !ErrorStatus, ei :: {-# UNPACK #-} !ErrorIndex }
    | SetRequest     { rid :: {-# UNPACK #-} !RequestId, es :: {-# UNPACK #-} !ErrorStatus, ei :: {-# UNPACK #-} !ErrorIndex }
    | GetBulk        { rid :: {-# UNPACK #-} !RequestId, es :: {-# UNPACK #-} !ErrorStatus, ei :: {-# UNPACK #-} !ErrorIndex }
    | Inform         { rid :: {-# UNPACK #-} !RequestId, es :: {-# UNPACK #-} !ErrorStatus, ei :: {-# UNPACK #-} !ErrorIndex }
    | V2Trap         { rid :: {-# UNPACK #-} !RequestId, es :: {-# UNPACK #-} !ErrorStatus, ei :: {-# UNPACK #-} !ErrorIndex }
    | Report         { rid :: {-# UNPACK #-} !RequestId, es :: {-# UNPACK #-} !ErrorStatus, ei :: {-# UNPACK #-} !ErrorIndex }
  deriving (Show, Eq)

-- | Coupla oid -> value
data Coupla = Coupla { oid :: !Oid, value :: !Value }
  deriving (Eq, Ord, Show)

-- | Variable bindings
newtype Suite = Suite [Coupla] deriving (Show, Monoid)

instance Eq Suite where
    (==) (Suite a) (Suite b) = sort a == sort b

-- ** Types describing header

-- | (snmp2 only) Community for 2(1) version
newtype Community = Community ByteString
  deriving (Show, Eq)

-- | (snmp3 only) Message Identifier (like RequestId in PDU)
newtype ID = ID Int32
  deriving (Show, Eq, Ord)

-- | (snmp3 only) Message max size must be > 484
newtype MaxSize = MaxSize Int
  deriving (Show, Eq, Ord)

-- | (snmp3 only) rfc3412, type for create message flag
data PrivAuth = NoAuthNoPriv | AuthNoPriv | AuthPriv
  deriving (Show, Eq, Ord, Enum)

-- | (snmp3 only) rfc3412, as PrivAuth
type Reportable = Bool

-- | (snmp3 only) rfc3412, message flag
data Flag = Flag !Reportable !PrivAuth
  deriving (Show, Eq)

-- | (snmp3 only) rfc3412, security model
data SecurityModel = UserBasedSecurityModel
  deriving (Show, Eq)

-- | (snmp3 only) rfc3412, security parameter
data SecurityParameter = SecurityParameter
    { authoritiveEngineId      :: !ByteString
    , authoritiveEngineBoots   :: {-# UNPACK #-} !Int32
    , authoritiveEngineTime    :: {-# UNPACK #-} !Int32
    , userName                 :: !ByteString
    , authenticationParameters :: !ByteString
    , privacyParameters        :: !ByteString
    }
  deriving (Eq, Show)

-- | (snmp3 only) rfc3412, types for ScopedPDU
newtype ContextEngineID = ContextEngineID ByteString
  deriving (Show, Eq)

newtype ContextName = ContextName ByteString
  deriving (Show, Eq)
----------------------------------------------------------------------------------------------------

newtype Tag = Tag Word8
  deriving (Eq, Ord, Show)

class Tagged a where
    tag :: a -> Tag

instance Tagged Request where
    tag GetRequest{} = Tag 0xa0
    tag GetNextRequest{} = Tag 0xa1
    tag GetResponse{} = Tag 0xa2
    tag SetRequest{} = Tag 0xa3
    tag GetBulk{} = Tag 0xa5
    tag Inform{} = Tag 0xa6
    tag V2Trap{} = Tag 0xa7
    tag Report{} = Tag 0xa8
    {-# INLINE tag #-}

----------------------------------------------------------------------------------------------------

-- | some exception
newtype SnmpException = SnmpException ErrorStatus
  deriving (Typeable, Eq)

instance Exception SnmpException

instance Show SnmpException where
    show (SnmpException (ErrorStatus 1)) = "tooBig"
    show (SnmpException (ErrorStatus 2)) = "noSuchName"
    show (SnmpException (ErrorStatus 3)) = "badValue"
    show (SnmpException (ErrorStatus 4)) = "readOnly"
    show (SnmpException (ErrorStatus 5)) = "genErr"
    show (SnmpException (ErrorStatus 6)) = "noAccess"
    show (SnmpException (ErrorStatus 7)) = "wrongType"
    show (SnmpException (ErrorStatus 8)) = "wrongLength"
    show (SnmpException (ErrorStatus 9)) = "wrongEncoding"
    show (SnmpException (ErrorStatus 10)) = "wrongValue"
    show (SnmpException (ErrorStatus 11)) = "noCreation"
    show (SnmpException (ErrorStatus 12)) = "inconsistentValue"
    show (SnmpException (ErrorStatus 13)) = "resourceUnavailable"
    show (SnmpException (ErrorStatus 14)) = "commitFailed"
    show (SnmpException (ErrorStatus 15)) = "undoFailed"
    show (SnmpException (ErrorStatus 16)) = "authorizationError"
    show (SnmpException (ErrorStatus 17)) = "notWritable"
    show (SnmpException (ErrorStatus 18)) = "inconsistentName"
    show (SnmpException (ErrorStatus 80)) = "General IO failure occured on the set request"
    show (SnmpException (ErrorStatus 81)) = "General SNMP timeout occured"
    show (SnmpException (ErrorStatus x)) = "Exception " ++ show x
    {-# INLINE show #-}

----------------------------------------------------------------------------------------

-- | initial new object, like mempty for monoid
class Construct a where
    initial :: a

instance Construct (Version -> Packet) where
    initial Version3 = V3Packet Version3 initial initial
    initial Version2 = V2Packet Version2 initial initial
    initial Version1 = V2Packet Version1 initial initial
    {-# INLINE initial #-}

instance Construct (Header V3) where
    initial = V3Header (ID 0) (MaxSize 65007) (Flag False NoAuthNoPriv) UserBasedSecurityModel initial
    {-# INLINE initial #-}

instance Construct (Header V2) where
    initial = V2Header (Community "")
    {-# INLINE initial #-}

instance Construct (PDU V3) where
    initial = ScopedPDU (ContextEngineID "") (ContextName "") initial
    {-# INLINE initial #-}

instance Construct (PDU V2) where
    initial = PDU initial initial
    {-# INLINE initial #-}

instance Construct SecurityParameter where
    initial = SecurityParameter "" 0 0 "" "" ""
    {-# INLINE initial #-}

instance Construct Suite where
    initial = Suite []
    {-# INLINE initial #-}

instance Construct Request where
    initial = GetRequest (RequestId 0) (ErrorStatus 0) (ErrorIndex 0)
    {-# INLINE initial #-}

----------------------------------------------------------------------------------------
-- | some universal getters, setters
class HasItem a where
    getHeader :: Packet -> Header a
    setHeader :: Header a -> Packet -> Packet
    getPDU :: Packet -> PDU a
    setPDU :: PDU a -> Packet -> Packet

instance HasItem V2 where
    getHeader (V2Packet _ x _) = x
    getHeader _ = undefined
    {-# INLINE getHeader #-}

    setHeader h (V2Packet v _ x) = V2Packet v h x
    setHeader _ _ = undefined
    {-# INLINE setHeader #-}

    getPDU (V2Packet _ _ x) = x
    getPDU _ = undefined
    {-# INLINE getPDU #-}

    setPDU p (V2Packet v h _) = V2Packet v h p
    setPDU _ _ = undefined
    {-# INLINE setPDU #-}

instance HasItem V3 where
    getHeader (V3Packet _ x _) = x
    getHeader _ = undefined
    {-# INLINE getHeader #-}

    setHeader h (V3Packet v _ x) = V3Packet v h x
    setHeader _ _ = undefined
    {-# INLINE setHeader #-}

    getPDU (V3Packet _ _ x) = x
    getPDU _ = undefined
    {-# INLINE getPDU #-}

    setPDU p (V3Packet v h _) = V3Packet v h p
    setPDU _ _ = undefined
    {-# INLINE setPDU #-}

----------------------------------------------------------------------------------------------------

getCommunity :: Header V2 -> Community
getCommunity (V2Header c) = c

setCommunity :: Community -> Header V2 -> Header V2
setCommunity c (V2Header _) = V2Header c

getID :: Header V3 -> ID
getID (V3Header i _ _ _ _) = i

getMaxSize :: Header V3 -> MaxSize
getMaxSize (V3Header _ i _ _ _) = i

getFlag :: Header V3 -> Flag
getFlag (V3Header _ _ i _ _) = i

getSecurityModel :: Header V3 -> SecurityModel
getSecurityModel (V3Header _ _ _ i _) = i

getSecurityParameter :: Header V3 -> SecurityParameter
getSecurityParameter (V3Header _ _ _ _ i) = i

getAuthoritiveEngineId :: Header V3 -> ByteString
getAuthoritiveEngineId = authoritiveEngineId . getSecurityParameter

getAuthoritiveEngineBoots :: Header V3 -> Int32
getAuthoritiveEngineBoots = authoritiveEngineBoots . getSecurityParameter

getAuthoritiveEngineTime :: Header V3 -> Int32
getAuthoritiveEngineTime = authoritiveEngineTime . getSecurityParameter

getUserName :: Header V3 -> ByteString
getUserName = userName . getSecurityParameter

getAuthenticationParameters :: Header V3 -> ByteString
getAuthenticationParameters = authenticationParameters . getSecurityParameter

getPrivacyParameters :: Header V3 -> ByteString
getPrivacyParameters = privacyParameters . getSecurityParameter

getContextEngineID :: PDU V3 -> ContextEngineID
getContextEngineID (ScopedPDU i _ _) = i
getContextEngineID _ = undefined

getContextName :: PDU V3 -> ContextName
getContextName (ScopedPDU _ i _) = i
getContextName _ = undefined

setID :: ID -> Header V3 -> Header V3
setID i (V3Header _ a b c d) = V3Header i a b c d

setMaxSize :: MaxSize -> Header V3 -> Header V3
setMaxSize i (V3Header a _ b c d) = V3Header a i b c d

setFlag :: Flag -> Header V3 -> Header V3
setFlag i (V3Header a b _ c d) = V3Header a b i c d

setSecurityModel :: SecurityModel -> Header V3 -> Header V3
setSecurityModel i (V3Header a b c _ d) = V3Header a b c i d

setSecurityParameter :: SecurityParameter -> Header V3 -> Header V3
setSecurityParameter i (V3Header a b c d _) = V3Header a b c d i

setAuthoritiveEngineId :: ByteString -> Header V3 -> Header V3
setAuthoritiveEngineId i (V3Header a b c d f) =
    V3Header a b c d (f { authoritiveEngineId = i })

setAuthoritiveEngineBoots :: Int32 -> Header V3 -> Header V3
setAuthoritiveEngineBoots i (V3Header a b c d f) =
    V3Header a b c d (f { authoritiveEngineBoots = i })

setAuthoritiveEngineTime :: Int32 -> Header V3 -> Header V3
setAuthoritiveEngineTime i (V3Header a b c d f) =
    V3Header a b c d (f { authoritiveEngineTime = i })

setUserName :: ByteString -> Header V3 -> Header V3
setUserName i (V3Header a b c d f) = V3Header a b c d (f { userName = i })

setAuthenticationParameters :: ByteString -> Header V3 -> Header V3
setAuthenticationParameters i (V3Header a b c d f) =
    V3Header a b c d (f { authenticationParameters = i })

setPrivacyParameters :: ByteString -> Header V3 -> Header V3
setPrivacyParameters i (V3Header a b c d f) =
    V3Header a b c d (f { privacyParameters = i })

setContextEngineID :: ContextEngineID -> PDU V3 -> PDU V3
setContextEngineID i (ScopedPDU _ b c) = ScopedPDU i b c
setContextEngineID _ _ = undefined

setContextName :: ContextName -> PDU V3 -> PDU V3
setContextName i (ScopedPDU a _ b) = ScopedPDU a i b
setContextName _ _ = undefined

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

getEngineIdP :: Packet -> EngineId
getEngineIdP p =
    let header = getHeader p :: Header V3
    in getAuthoritiveEngineId header

setEngineIdP :: EngineId -> Packet -> Packet
setEngineIdP x p =
  let header = getHeader p :: Header V3
      newHeader = setAuthoritiveEngineId x header
  in setHeader newHeader p

getEngineBootsP :: Packet -> EngineBootId
getEngineBootsP p =
    let header = getHeader p :: Header V3
    in getAuthoritiveEngineBoots header

setEngineBootsP :: EngineBootId -> Packet -> Packet
setEngineBootsP x p =
    let header = getHeader p :: Header V3
        newHeader = setAuthoritiveEngineBoots x header
    in setHeader newHeader p

getEngineTimeP :: Packet -> Int32
getEngineTimeP p =
    let header = getHeader p :: Header V3
    in getAuthoritiveEngineTime header

setEngineTimeP :: Int32 -> Packet -> Packet
setEngineTimeP x p =
    let header = getHeader p :: Header V3
        newHeader = setAuthoritiveEngineTime x header
    in setHeader newHeader p

setReportableP :: Reportable -> Packet -> Packet
setReportableP r p =
    let header = getHeader p :: Header V3
        Flag _ a = getFlag header
        newHeader = setFlag (Flag r a) header
    in setHeader newHeader p

setPrivAuthP :: PrivAuth -> Packet -> Packet
setPrivAuthP x p =
    let header = getHeader p :: Header V3
        Flag r _ = getFlag header
        newHeader = setFlag (Flag r x) header
    in setHeader newHeader p

setUserNameP :: ByteString -> Packet -> Packet
setUserNameP x p =
    let header = getHeader p :: Header V3
        sp = getSecurityParameter header
        newHeader = setSecurityParameter (sp { userName = x }) header
    in setHeader newHeader p

setAuthenticationParametersP :: ByteString -> Packet -> Packet
setAuthenticationParametersP x p =
    let header = getHeader p :: Header V3
        sp = getSecurityParameter header
        newHeader = setSecurityParameter (sp { authenticationParameters = x }) header
    in setHeader newHeader p

getAuthenticationParametersP :: Packet -> ByteString
getAuthenticationParametersP p =
    let header = getHeader p :: Header V3
    in authenticationParameters (getSecurityParameter header)

setPrivParametersP :: ByteString -> Packet -> Packet
setPrivParametersP x p =
    let header = getHeader p :: Header V3
        sp = getSecurityParameter header
        newHeader = setSecurityParameter (sp { privacyParameters = x }) header
    in setHeader newHeader p

getPrivParametersP :: Packet -> ByteString
getPrivParametersP p =
    let header = getHeader p :: Header V3
    in privacyParameters $ getSecurityParameter header

getVersion :: Packet -> Version
getVersion (V2Packet v _ _) = v
getVersion (V3Packet v _ _) = v

getRid :: Packet -> RequestId
getRid (V2Packet _ _ (PDU r _)) = rid r
getRid (V3Packet _ _ (ScopedPDU _ _ (PDU r _))) = rid r
getRid _ = undefined

setRid :: RequestId -> Packet -> Packet
setRid r (V2Packet v h (PDU req s)) = V2Packet v h (PDU req { rid = r } s)
setRid r (V3Packet v h (ScopedPDU a b (PDU req s))) = V3Packet v h (ScopedPDU a b (PDU req { rid = r } s))
setRid _ _ = undefined

getErrorStatus :: Packet -> ErrorStatus
getErrorStatus (V2Packet _ _ (PDU r _)) = es r
getErrorStatus (V3Packet _ _ (ScopedPDU _ _ (PDU r _))) = es r
getErrorStatus _ = undefined

setErrorStatus :: ErrorStatus -> Packet -> Packet
setErrorStatus e (V2Packet v h (PDU req s)) = V2Packet v h (PDU req { es = e } s)
setErrorStatus e (V3Packet v h (ScopedPDU a b (PDU req s))) = V3Packet v h (ScopedPDU a b (PDU req { es = e } s))
setErrorStatus _ _ = undefined

getSuite :: Packet -> Suite
getSuite (V2Packet _ _ (PDU _ r)) = r
getSuite (V3Packet _ _ (ScopedPDU _ _ (PDU _ r))) = r
getSuite _ = undefined

setSuite :: Suite -> Packet -> Packet
setSuite s (V2Packet v h (PDU req _)) = V2Packet v h (PDU req s)
setSuite s (V3Packet v h (ScopedPDU a b (PDU req _))) = V3Packet v h (ScopedPDU a b (PDU req s))
setSuite _ _ = undefined

getRequest :: Packet -> Request
getRequest (V2Packet _ _ (PDU r _)) = r
getRequest (V3Packet _ _ (ScopedPDU _ _ (PDU r _))) = r
getRequest _ = undefined

setRequest :: Request -> Packet -> Packet
setRequest req (V2Packet v h (PDU _ s)) = V2Packet v h (PDU req s)
setRequest req (V3Packet v h (ScopedPDU a b (PDU _ s))) = V3Packet v h (ScopedPDU a b (PDU req s))
setRequest _ _ = undefined
----------------------------------------------------------------------------------------------------

newtype Size = Size Int deriving (Eq, Show)
type ErrorCode = Int

putLength :: Int -> Put
putLength = putSize . Size

getLength :: Get Int
getLength = do
    Size i <- getSize
    return i

putTag :: Tag -> Put
putTag (Tag t) = putWord8 t
{-# INLINE putTag #-}

dropTag :: Tag -> ErrorCode -> Get ()
dropTag x e = do
    t <- getTag
    when (t /= x) $ fail (show e)
-- {-# INLINE dropTag #-}

getTag :: Get Tag
getTag = Tag <$> getWord8
{-# INLINE getTag #-}

putIntegral :: Integral a => a -> Put
putIntegral = putOctets . bytesOfInt . fromIntegral

putIntegralU :: Integral a => a -> Put
putIntegralU = putOctets . bytesOfUInt . fromIntegral

putBS :: ByteString -> Put
putBS bs = do
    putLength (B.length bs)
    putByteString bs

getBS :: Get ByteString
getBS = getLength >>= getByteString

putOctets :: [Word8] -> Put
putOctets bytes = do
    putLength (length bytes)
    mapM_ putWord8 bytes

getOctets :: Get ByteString
getOctets = getLength >>= getBytes

----------------------------------------------------------------------------------------------------

{- | uintOfBytes returns the number of bytes and the unsigned integer represented by the bytes -}
uintOfBytes :: ByteString -> (Int, Int)
uintOfBytes b = (B.length b, B.foldl (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0 b)

--bytesOfUInt i = B.unfoldr (\x -> if x == 0 then Nothing else Just (fromIntegral (x .&. 0xff), x `shiftR` 8)) i
bytesOfUInt :: Int -> [Word8]
bytesOfUInt x = reverse (list x)
  where
    list i = if i <= 0xff
             then [fromIntegral i]
             else (fromIntegral i .&. 0xff) : list (i `shiftR` 8)

{- | intOfBytes returns the number of bytes in the list and
   the represented integer by a two's completement list of bytes -}
intOfBytes :: ByteString -> (Int, Int)
intOfBytes b
    | B.length b == 0 = (0, 0)
    | otherwise       = (len, if isNeg then -(maxIntLen - v + 1) else v)
  where
    (len, v)  = uintOfBytes b
    maxIntLen = 2 ^ (8 * len) - 1
    isNeg     = testBit (B.head b) 7

{- | bytesOfInt convert an integer into a two's completemented list of bytes -}
bytesOfInt :: Int -> [Word8]
bytesOfInt i
    | i > 0  = if testBit (head uints) 7 then 0 : uints else uints
    | i == 0 = [0]
    | otherwise  = if testBit (head nints) 7 then nints else 0xff : nints
  where
    uints = bytesOfUInt (abs i)
    nints = reverse . plusOne . reverse . map complement $ uints
    plusOne []     = [1]
    plusOne (x:xs) = if x == 0xff then 0 : plusOne xs else (x+1) : xs

putVarEncodingIntegral :: (Bits i, Integral i) => i -> ByteString
putVarEncodingIntegral i = B.reverse $ B.unfoldr genOctets (i,True)
  where
    genOctets (x,first)
        | x > 0     =
            let out = fromIntegral (x .&. 0x7F) .|. (if first then 0 else 0x80)
             in Just (out, (shiftR x 7, False))
        | otherwise = Nothing

----------------------------------------------------------------------------------------------------

getSize :: Get Size
getSize = do
    l1 <- fromIntegral <$> getWord8
    if testBit l1 7
        then case clearBit l1 7 of
                 0   -> return (Size 0)
                 len -> Size . uintbs <$> getBytes len
        else return (Size l1)
  where
    {- uintbs return the unsigned int represented by the bytes -}
    uintbs = B.foldl (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0

putSize :: Size -> Put
putSize (Size i)
    | i >= 0 && i <= 0x7f = putWord8 (fromIntegral i)
    | i < 0     = fail "8"
    | otherwise = mapM_ putWord8 (lenbytes : lw)
  where
    lw       = bytesOfUInt (fromIntegral i)
    lenbytes = fromIntegral (length lw .|. 0x80)

putOid :: Oid -> Put
putOid (Oid oid) =
    case oid of
        (id1:id2:subIds) ->
            let eoidclass = fromIntegral (id1 * 40 + id2)
                bs = (B.cons eoidclass . B.concat . map encode') subIds
             in putBS bs
        _ -> fail "put oi"  -- TODO: Set error code
  where
    encode' 0 = B.singleton 0
    encode' x = putVarEncodingIntegral x

getOid :: Get Oid
getOid = do
    bs <- getBS
    let (x:xs) = B.unpack bs
        firstOI = fromIntegral (x `div` 40)
        secondOI = fromIntegral (x `mod` 40)
        groupOID :: [Word8] -> [Word16]
        groupOID = map (foldl (\acc n -> (acc `shiftL` 7) + fromIntegral n) 0) . groupSubOID
        groupSubOIDHelper [] = Nothing
        groupSubOIDHelper s = Just $ spanSubOIDbound s
        groupSubOID :: [Word8] -> [[Word8]]
        groupSubOID = unfoldr groupSubOIDHelper
        spanSubOIDbound [] = ([], [])
        spanSubOIDbound (a:as) = if testBit a 7 then (clearBit a 7 : ys, zs) else ([a], as)
          where (ys, zs) = spanSubOIDbound as
    return $ Oid (firstOI : secondOI : groupOID xs)

putValue :: Value -> Put
putValue (Integer i)         = putTag (Tag 0x02) >> putIntegral i
putValue (BitString bs)      = putTag (Tag 0x03) >> putBS bs
putValue (OctetString bs)    = putTag (Tag 0x04) >> putBS bs
putValue Null              = putTag (Tag 0x05) >> putWord8 0
putValue (OI oid)            = putTag (Tag 0x06) >> putOid oid
putValue (IpAddress a b c d) = putTag (Tag 0x40) >> putOctets [a, b, c, d]
putValue (Counter32 i)       = putTag (Tag 0x41) >> putIntegralU i
putValue (Gauge32 i)         = putTag (Tag 0x42) >> putIntegralU i
putValue (TimeTicks i)       = putTag (Tag 0x43) >> putIntegralU i
putValue (Opaque bs)         = putTag (Tag 0x44) >> putBS bs
putValue (NsapAddress bs)    = putTag (Tag 0x45) >> putBS bs
putValue (Counter64 i)       = putTag (Tag 0x46) >> putIntegral i
putValue (UInteger32 i)      = putTag (Tag 0x47) >> putIntegralU i
putValue NoSuchObject      = putTag (Tag 0x80) >> putWord8 0
putValue NoSuchInstance    = putTag (Tag 0x81) >> putWord8 0
putValue EndOfMibView      = putTag (Tag 0x82) >> putWord8 0

getValue :: Get Value
getValue = do
    Tag t <- getTag
    case t of
        0x02 -> Integer . fromIntegral . snd . intOfBytes <$> getOctets
        0x03 -> BitString <$> getBS
        0x04 -> OctetString <$> getBS
        0x05 -> Null <$ getWord8
        0x06 -> OI <$> getOid
        0x40 -> do
            _ <- getSize
            IpAddress <$> getWord8 <*> getWord8 <*> getWord8 <*> getWord8
        0x41 -> Counter32 . fromIntegral . snd . uintOfBytes <$> getOctets
        0x42 -> Gauge32 . fromIntegral . snd . uintOfBytes <$> getOctets
        0x43 -> TimeTicks . fromIntegral . snd . uintOfBytes <$> getOctets
        0x44 -> Opaque <$> getBS
        0x45 -> NsapAddress <$> getBS
        0x46 -> Counter64 . fromIntegral . snd . uintOfBytes <$> getOctets
        0x47 -> UInteger32 . fromIntegral . snd . uintOfBytes <$> getOctets
        0x80 -> NoSuchObject <$ getWord8
        0x81 -> NoSuchInstance <$ getWord8
        0x82 -> EndOfMibView <$ getWord8
        _ -> fail "9"

instance Serialize Size where
    put = putSize
    {-# INLINE put #-}

    get = getSize
    {-# INLINE get #-}

instance Serialize Value where
    put = putValue
    {-# INLINE put #-}

    get = getValue
    {-# INLINE get #-}

----------------------------------------------------------------------------------------------------

getInteger :: Get Int32
getInteger = getValue >>= \case
    (Integer i) -> return i
    _ -> fail "7"

getOctetString :: Get ByteString
getOctetString = getValue >>= \case
    (OctetString os) -> return os
    _ -> fail "7"

getOI :: Get Oid
getOI = getValue >>= \case
    (OI oid) -> return oid
    _ -> fail "7"

----------------------------------------------------------------------------------------------------

instance Serialize Version where
    put = putValue . Integer . mpModel
      where
        mpModel Version1 = 0
        mpModel Version2 = 1
        mpModel Version3 = 3
    {-# INLINE put #-}

    get = getInteger >>= toVersion
      where
        toVersion 0 = return Version1
        toVersion 1 = return Version2
        toVersion 3 = return Version3
        toVersion _ = fail "10"
    {-# INLINE get #-}

instance Serialize Community where
    put (Community bs) = putValue (OctetString bs)
    {-# INLINE put #-}

    get = Community <$> getOctetString
    {-# INLINE get #-}

instance Serialize (Header V2) where
    put (V2Header c) = put c
    {-# INLINE put #-}

    get = V2Header <$> get
    {-# INLINE get #-}

instance Serialize ID where
    put (ID x) = putValue (Integer x)
    {-# INLINE put #-}

    get = ID <$> getInteger
    {-# INLINE get #-}

instance Serialize MaxSize where
    put (MaxSize x) = putValue (Integer $ fromIntegral x)
    {-# INLINE put #-}

    get = MaxSize . fromIntegral <$> getInteger
    {-# INLINE get #-}

-- [ 0 - Reportable | 1 - Priv | 2 - Auth | _ | _ | _ | _ | _ ] - bits
instance Serialize Flag where
    put (Flag r pa) =
        let zero = zeroBits :: Word8
            reportable = if r then setBit zero 0 else zero
            privauth = case pa of
                           NoAuthNoPriv -> zero
                           AuthNoPriv -> setBit zero 2
                           AuthPriv -> setBit zero 1 .|. setBit zero 2
            flag = reportable .|. privauth
         in putValue $ OctetString (B.pack [flag])
    {-# INLINE put #-}

    get = getOctetString >>= toFlag
      where
        toFlag f
            | B.length f /= 1 = fail "10"
            | otherwise =
                let [w] = B.unpack f
                    reportable = testBit w 0
                    flag = Flag reportable
                 in case (testBit w 1, testBit w 2) of
                        (True, True) -> return $ flag AuthPriv
                        (False, False) -> return $ flag NoAuthNoPriv
                        (False, True) -> return $ flag AuthNoPriv
                        _ -> fail "10" -- SnmpException 10
    {-# INLINE get #-}

instance Serialize SecurityModel where
    put UserBasedSecurityModel = putValue (Integer 3)
    {-# INLINE put #-}

    get = getInteger >>= toSecurityModel
      where
        toSecurityModel 3 = return UserBasedSecurityModel
        toSecurityModel _ = fail "7" -- SnmpException 7
    {-# INLINE get #-}

instance Serialize SecurityParameter where
    put SecurityParameter{..} = do
        putTag (Tag 0x04)
        putNested putLength $ do
            putTag (Tag 0x30)
            putNested putLength putSecurityParameter
      where
        putSecurityParameter = do
            putValue (OctetString authoritiveEngineId)
            putValue (Integer $ fromIntegral authoritiveEngineBoots)
            putValue (Integer $ fromIntegral authoritiveEngineTime)
            putValue (OctetString userName)
            putValue (OctetString authenticationParameters)
            putValue (OctetString privacyParameters)
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x04) 9
        getNested getLength $ do
            dropTag (Tag 0x30) 9
            getNested getLength getSecurityParameter'
      where
        getSecurityParameter' :: Get SecurityParameter
        getSecurityParameter' = SecurityParameter
                              <$> getOctetString
                              <*> (fromIntegral <$> getInteger)
                              <*> (fromIntegral <$> getInteger)
                              <*> getOctetString
                              <*> getOctetString
                              <*> getOctetString
    {-# INLINE get #-}

instance Serialize (Header V3) where
    put (V3Header iD maxSize flag securityModel securityParameter) = do
        putTag (Tag 0x30)
        putNested putLength $ do
            put iD
            put maxSize
            put flag
            put securityModel
        put securityParameter
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x30) 9
        getNested getLength (V3Header <$> get <*> get <*> get <*> get) <*> get
    {-# INLINE get #-}

instance Serialize RequestId where
    put (RequestId rid) = putValue (Integer $ fromIntegral rid)
    {-# INLINE put #-}

    get = RequestId <$> getInteger
    {-# INLINE get #-}

instance Serialize ErrorStatus where
    put (ErrorStatus es) = putValue (Integer $ fromIntegral es)
    {-# INLINE put #-}

    get = ErrorStatus <$> getInteger
    {-# INLINE get #-}

instance Serialize ErrorIndex where
    put (ErrorIndex ei) = putValue (Integer $ fromIntegral ei)
    {-# INLINE put #-}

    get = ErrorIndex <$> getInteger
    {-# INLINE get #-}

instance Serialize Suite where
    put (Suite vbs) = putTag (Tag 0x30) >> putNested putLength (mapM_ put vbs)
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x30) 9
        Suite <$> getNested getLength (getSuite' [])
      where
        getSuite' xs = do
            check <- isEmpty
            if check
                then return $ reverse xs
                else do
                    coupla <- get
                    getSuite' (coupla : xs)
    {-# INLINE get #-}

instance Serialize Coupla where
    put (Coupla oid val) = do
        putTag (Tag 0x30)
        putNested putLength (putValue (OI oid) >> putValue val)
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x30) 9
        getNested getLength (Coupla <$> getOI <*> getValue)
    {-# INLINE get #-}

instance Serialize (PDU V2) where
    put (PDU request suite) = do
        putTag (tag request)
        putNested putLength $ do
            put (rid request)
            put (es request)
            put (ei request)
            put suite
    {-# INLINE put #-}

    get = do
        Tag t <- getTag
        let request = case t of
                0xa0 -> GetRequest
                0xa1 -> GetNextRequest
                0xa2 -> GetResponse
                0xa3 -> SetRequest
                0xa5 -> GetBulk
                0xa6 -> Inform
                0xa7 -> V2Trap
                0xa8 -> Report
                _ -> fail "9"
        getNested getLength (PDU <$> (request <$> get <*> get <*> get) <*> get)
    {-# INLINE get #-}

instance Serialize ContextEngineID where
    put (ContextEngineID bs) = putValue (OctetString bs)
    {-# INLINE put #-}

    get = ContextEngineID <$> getOctetString
    {-# INLINE get #-}

instance Serialize ContextName where
    put (ContextName bs) = putValue (OctetString bs)
    {-# INLINE put #-}

    get = ContextName <$> getOctetString
    {-# INLINE get #-}

instance Serialize (PDU V3) where
    put (ScopedPDU contextEngine contextName pdu) = do
        putTag (Tag 0x30)
        putNested putLength (put contextEngine >> put contextName >> put pdu)
    put (CryptedPDU bs) = putValue (OctetString bs)
    {-# INLINE put #-}

    get = do
        Tag t <- getTag
        case t of
            0x30 -> getNested getLength (ScopedPDU <$> get <*> get <*> get)
            0x04 -> CryptedPDU <$> getBS
            _ -> fail "9"
    {-# INLINE get #-}

instance Serialize Packet where
    put (V2Packet version header body) = do
        putTag (Tag 0x30)
        putNested putLength (put version >> put header >> put body)
    put (V3Packet version header body) = do
        putTag (Tag 0x30)
        putNested putLength (put version >> put header >> put body)
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x30) 9
        getNested getLength getAll
      where
        getAll = get >>= getPacket
        getPacket Version1 = V2Packet Version1 <$> get <*> get
        getPacket Version2 = V2Packet Version2 <$> get <*> get
        getPacket Version3 = V3Packet Version3 <$> get <*> get
    {-# INLINE get #-}

-------------------------------------------------------------------------------------------------------------

cleanPass :: ByteString
cleanPass = B.pack $ replicate 12 0x00

data PrivType = DES | AES deriving (Show, Ord, Eq)
data AuthType = MD5 | SHA deriving (Show, Ord, Eq)
newtype Key = Key ByteString deriving (Show, Ord, Eq)
newtype Password = Password ByteString deriving (Show, Ord, Eq)

hash :: (BA.ByteArray a) => AuthType -> ByteString -> a
hash MD5 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.MD5)
hash SHA bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA1)

hashlazy :: (BA.ByteArray a) => AuthType -> BL.ByteString -> a
hashlazy MD5 bs = BA.convert (Hash.hashlazy bs :: Hash.Digest Hash.MD5)
hashlazy SHA bs = BA.convert (Hash.hashlazy bs :: Hash.Digest Hash.SHA1)

hmac :: (BA.ByteArrayAccess key, BA.ByteArray msg) => AuthType -> key -> msg -> ByteString
hmac MD5 key msg = BA.convert (HMAC.hmac key msg :: HMAC.HMAC Hash.MD5)
hmac SHA key msg = BA.convert (HMAC.hmac key msg :: HMAC.HMAC Hash.SHA1)

-- | (only V3) sign Packet
signPacket :: AuthType -> Key -> Packet -> Packet
signPacket at (Key key) packet =
    let packetAsBin = encode packet
        sign = B.take 12 $ hmac at key packetAsBin
    in setAuthenticationParametersP sign packet

-- | create auth key from password and context engine id
passwordToKey :: AuthType -> Password -> EngineId -> Key
passwordToKey at (Password pass) eid =
  let buf = (BL.take 1048576 . BL.fromChunks . repeat) pass
      authKey = hashlazy at buf
  in Key $ hash at (authKey <> eid <> authKey)

-----------------------------------------------------------------------------------------------------

type EngineBootId = Int32
type PrivacyParameter = ByteString
type EngineId = ByteString
type Salt = ByteString
type Encrypted = ByteString
type Raw = ByteString
type Rand32 = Int32
type Rand64 = Int64

desEncrypt :: Key -> EngineBootId -> Rand32 -> Raw -> (Encrypted, Salt)
desEncrypt (Key privKey) engineBoot localInt dataToEncrypt =
    let desKey = B.take 8 privKey
        preIV = B.drop 8 $ B.take 16 privKey
        salt = toSalt engineBoot localInt
        ivR = B.pack $ zipWith xor (B.unpack preIV) (B.unpack salt)
        Just iv = Priv.makeIV ivR :: Maybe (Priv.IV Priv.DES)
        -- Right key = Priv.makeKey desKey
        Priv.CryptoPassed des = Priv.cipherInit desKey :: Priv.CryptoFailable Priv.DES
        tailLen = (8 - B.length dataToEncrypt `rem` 8) `rem` 8
        tailB = B.replicate tailLen 0x00
    in (Priv.cbcEncrypt des iv (dataToEncrypt <> tailB), salt)

type EngineTime = Int32

aesEncrypt :: Key -> EngineBootId -> EngineTime -> Rand64 -> Raw -> (Encrypted, Salt)
aesEncrypt (Key privKey) engineBoot engineTime rcounter dataToEncrypt =
    let aesKey = B.take 16 privKey
        salt = wToBs rcounter
        Just iv = Priv.makeIV $ toSalt engineBoot engineTime <> salt :: Maybe (Priv.IV Priv.AES128)
        -- Right key = Priv.makeKey aesKey
        Priv.CryptoPassed aes = Priv.cipherInit aesKey :: Priv.CryptoFailable Priv.AES128
    in (Priv.cfbEncrypt aes iv dataToEncrypt, salt)

wToBs :: Int64 -> ByteString
wToBs x = B.pack
    [ fromIntegral (x `shiftR` 56 .&. 0xff)
    , fromIntegral (x `shiftR` 48 .&. 0xff)
    , fromIntegral (x `shiftR` 40 .&. 0xff)
    , fromIntegral (x `shiftR` 32 .&. 0xff)
    , fromIntegral (x `shiftR` 24 .&. 0xff)
    , fromIntegral (x `shiftR` 16 .&. 0xff)
    , fromIntegral (x `shiftR` 8 .&. 0xff)
    , fromIntegral (x `shiftR` 0 .&. 0xff)
    ]

toSalt :: Int32 -> Int32 -> ByteString
toSalt x y = B.pack
    [ fromIntegral (x `shiftR` 24 .&. 0xff)
    , fromIntegral (x `shiftR` 16 .&. 0xff)
    , fromIntegral (x `shiftR`  8 .&. 0xff)
    , fromIntegral (x `shiftR`  0 .&. 0xff)
    , fromIntegral (y `shiftR` 24 .&. 0xff)
    , fromIntegral (y `shiftR` 16 .&. 0xff)
    , fromIntegral (y `shiftR`  8 .&. 0xff)
    , fromIntegral (y `shiftR`  0 .&. 0xff)
    ]

desDecrypt :: Key -> Salt -> Encrypted -> Raw
desDecrypt (Key privKey) privParameters dataToDecrypt =
    let desKey = B.take 8 privKey
        preIV = B.drop 8 $ B.take 16 privKey
        salt = privParameters
        ivR = zipWith xor (B.unpack preIV) (B.unpack salt)
        Just iv = (Priv.makeIV (B.pack ivR) :: Maybe (Priv.IV Priv.DES))
        -- Right key = Priv.makeKey desKey
        Priv.CryptoPassed des = Priv.cipherInit desKey :: Priv.CryptoFailable Priv.DES
    in stripBS $ Priv.cbcDecrypt des iv dataToDecrypt

aesDecrypt :: Key -> Salt -> EngineBootId -> EngineTime -> Encrypted -> Raw
aesDecrypt (Key privKey) salt engineBoot engineTime dataToDecrypt =
    let aesKey = B.take 16 privKey
        ivR = toSalt engineBoot engineTime <> salt
        Just iv = (Priv.makeIV ivR :: Maybe (Priv.IV Priv.AES128))
        -- Right key = Priv.makeKey aesKey
        Priv.CryptoPassed aes = Priv.cipherInit aesKey :: Priv.CryptoFailable Priv.AES128
    in stripBS $ Priv.cfbDecrypt aes iv dataToDecrypt

stripBS :: ByteString -> ByteString
stripBS bs =
    let bs' = B.drop 1 bs
        l1 = fromIntegral (B.head bs')
    in if testBit l1 7
        then case clearBit l1 7 of
                  0   -> throw $ SnmpException (ErrorStatus 12)
                  len ->
                    let size = uintbs (B.take len (B.drop 1 bs'))
                    in B.take (size + len + 2) bs
        else B.take (l1 + 2) bs
  where
    {- uintbs return the unsigned int represented by the bytes -}
    uintbs = B.foldl (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0

