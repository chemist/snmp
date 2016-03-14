{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# OPTIONS_GHC -funbox-small-strict-fields #-}

module Network.Protocol.Snmp.Types
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
    , MessageID(..)
    , MaxSize(..)
    , Flag(..)
    , ErrorIndex(..)
    , ErrorStatus(..)
    , RequestID(..)
    , SecurityModel(..)
    , SecurityParameter(..)
    , Reportable
    , Login(..)
    , PrivAuth(..)
    , EngineBoot(..)
    , PrivacyParameter(..)
    , AuthenticationParameter(..)
    , EngineTime(..)
    , EngineID(..)
    -- ** PDU
    , PDU (..)
    -- *** PDU universal
    , RequestType(..)
    , Request(..)
    , Suite(..)
    , Coupla(..)
    -- *** PDU snmpV3
    , ContextEngineID(..)
    , ContextName(..)
    -- * ASN.1 types
    , Tag(..)
    , Size(..)
    ) where

import           Data.ByteString (ByteString)
import           Data.Int        (Int32)
import           Data.List       (intercalate, sort)
import           Data.Word       (Word16, Word32, Word64, Word8)

newtype Oid = Oid [Word16]
  deriving (Eq, Ord, Monoid)

instance Show Oid where
    show (Oid ls) = intercalate "." . map show $ ls
    {-# INLINE show #-}

data Value
    = Integer !Int32
    | BitString !ByteString
    | OctetString !ByteString
    | Null
    | OI !Oid
    | IpAddress !Word8
                !Word8
                !Word8
                !Word8
    | Counter32 !Word32
    | Gauge32 !Word32
    | TimeTicks !Word32
    | Opaque !ByteString
    | NsapAddress !ByteString
    | Counter64 !Word64
    | UInteger32 !Word32
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
  deriving (Eq, Enum, Show)

-- | Top level type, which describe snmp packet
data Packet where
    V2Packet :: Version -> Header V2 -> PDU V2 -> Packet
    V3Packet :: Version -> Header V3 -> PDU V3 -> Packet
  deriving (Eq, Show)

-- | Snmp header without version tag
data Header a where
    V2Header :: Community -> Header V2
    V3Header :: MessageID -> MaxSize -> Flag -> SecurityModel -> SecurityParameter -> Header V3

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
newtype RequestID = RequestID Int32
  deriving (Show, Eq, Ord, Num, Bounded, Enum)

-- | Error status
newtype ErrorStatus = ErrorStatus Int32
  deriving (Show, Eq, Ord, Num, Bounded, Enum)

-- | Error index
newtype ErrorIndex = ErrorIndex Int32
  deriving (Show, Eq, Ord, Num, Bounded, Enum)

-- | Request types
data RequestType
    = GetRequest
    | GetNextRequest
    | GetResponse
    | SetRequest
    | GetBulkRequest
    | Inform
    | V2Trap
    | Report
  deriving (Show, Eq, Ord, Enum)

data Request = Request
    { rt  :: !RequestType
    , rid :: !RequestID
    , es  :: !ErrorStatus
    , ei  :: !ErrorIndex
    } deriving (Show, Eq)

-- | Coupla oid -> value
data Coupla = Coupla
    { oid   :: !Oid
    , value :: !Value
    } deriving (Eq, Ord, Show)

-- | Variable bindings
newtype Suite = Suite [Coupla]
  deriving (Show, Monoid)

instance Eq Suite where
    (==) (Suite a) (Suite b) = sort a == sort b

-- ** Types describing header

-- | (snmp2 only) Community for 2(1) version
newtype Community = Community ByteString
  deriving (Show, Eq)

-- | (snmp3 only) Message Identifier (like RequestID in PDU)
newtype MessageID = MessageID Int32
  deriving (Show, Eq, Ord, Num, Bounded, Enum)

-- | (snmp3 only) Message max size must be > 484
newtype MaxSize = MaxSize Int
  deriving (Show, Eq, Ord, Num)

-- | (snmp3 only) rfc3412, type for create message flag
data PrivAuth = NoAuthNoPriv
              | AuthNoPriv
              | AuthPriv
  deriving (Show, Eq, Ord, Enum)

-- | (snmp3 only) rfc3412, as PrivAuth
type Reportable = Bool

-- | (snmp3 only) rfc3412, message flag
data Flag = Flag !Reportable !PrivAuth
  deriving (Show, Eq)

-- | (snmp3 only) rfc3412, security model
data SecurityModel = UserBasedSecurityModel
  deriving (Show, Eq)

newtype PrivacyParameter = PrivacyParameter ByteString
  deriving (Show, Eq)

newtype AuthenticationParameter = AuthenticationParameter ByteString
  deriving (Show, Eq)

newtype EngineID = EngineID ByteString
  deriving (Eq, Ord, Show)

newtype EngineTime = EngineTime Int32
  deriving (Eq, Ord, Num, Bounded, Enum, Show)

newtype EngineBoot = EngineBoot Int32
  deriving (Eq, Ord, Num, Bounded, Enum, Show)

-- | (snmp3 only) Security user name
newtype Login = Login ByteString
  deriving (Eq, Ord, Show)

-- | (snmp3 only) rfc3412, security parameter
data SecurityParameter = SecurityParameter
    { authoritativeEngineID    :: !EngineID
    , authoritativeEngineBoots :: !EngineBoot
    , authoritativeEngineTime  :: !EngineTime
    , userName                 :: !Login
    , authenticationParameters :: !AuthenticationParameter
    , privacyParameters        :: !PrivacyParameter
    } deriving (Eq, Show)

-- | (snmp3 only) rfc3412, types for ScopedPDU
newtype ContextEngineID = ContextEngineID ByteString
  deriving (Show, Eq)

newtype ContextName = ContextName ByteString
  deriving (Show, Eq)

-- | ASN1 tag
newtype Tag = Tag Word8
  deriving (Eq, Ord, Show)

-- | ASN1 size
newtype Size = Size Int
  deriving (Eq, Show)

