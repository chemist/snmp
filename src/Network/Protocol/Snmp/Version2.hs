{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleInstances #-}
module Network.Protocol.Snmp.Version2 
( Version(..)
, Coupla(..)
, Suite(..)
, Community(..)
, Request(..)
, PDU(..)
, RequestId
, Header(..)
, Pack(..)
)
where

import Data.ASN1.Parse
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ByteString (ByteString, pack, unpack)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Control.Applicative
import Network.Protocol.Snmp.Types
import Data.Monoid
import Data.Bits
import Data.Word
import Debug.Trace

newtype Community = Community ByteString deriving (Show, Eq)

instance ASN1Object Community where
    toASN1 (Community x) xs = OctetString x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        OctetString x <- getNext
        return $ Community x


