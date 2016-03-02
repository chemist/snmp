module Network.Protocol.Snmp.Exception
    (
      SnmpException(..)
    ) where

import           Control.Exception
import           Data.Typeable

import           Network.Protocol.Snmp.Types (ErrorStatus (..))

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

