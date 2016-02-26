{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main where

import           Data.ByteString                      (ByteString, pack)
-- import           Data.List                            (sort)
import           Data.Serialize
import           Network.Protocol.Snmp
import           Test.Framework                       (Test, defaultMain,
                                                       testGroup)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.QuickCheck
-- import           Test.QuickCheck.Gen                  (oneof)

main :: IO ()
main = defaultMain tests

tests :: [Test]
tests = [ testGroup "encode decode"
          [ testProperty "value" (prop_Encode :: Value -> Bool)
          , testProperty "version" (prop_Encode :: Version -> Bool)
          , testProperty "header v2" (prop_Encode :: Header V2 -> Bool)
          , testProperty "ID" (prop_Encode :: ID -> Bool)
          , testProperty "MaxSize" (prop_Encode :: MaxSize -> Bool)
          , testProperty "Flag" (prop_Encode :: Flag -> Bool)
          , testProperty "SecurityParameter" (prop_Encode :: SecurityParameter -> Bool)
          , testProperty "header v3" (prop_Encode :: Header V3 -> Bool)
          , testProperty "suite" (prop_Encode :: Suite -> Bool)
          , testProperty "PDU v2" (prop_Encode :: PDU V2 -> Bool)
          , testProperty "PDU v3" (prop_Encode :: PDU V3 -> Bool)
          , testProperty "Packet" (prop_Encode :: Packet -> Bool)
          ]
        ]

prop_Encode :: (Serialize a, Eq a) => a -> Bool
prop_Encode xs = Right xs == decode (encode xs)

instance Arbitrary Oid where
    arbitrary = Oid <$> oilist
      where
        oilist = do
            a <- choose (0,2)
            b <- choose (0,39)
            s <- choose (0,30)
            l <- take s <$> infiniteList
            return $ a : b : l

instance Arbitrary Version where
    arbitrary = oneof [ pure Version1, pure Version2, pure Version3 ]

instance Arbitrary (Header V2) where
    arbitrary = V2Header . Community <$> arbitrary

instance Arbitrary ID where
    arbitrary = ID <$> arbitrary

instance Arbitrary MaxSize where
    arbitrary = MaxSize <$> arbitrary

instance Arbitrary (Header V3) where
    arbitrary = V3Header <$> arbitrary
                         <*> arbitrary
                         <*> arbitrary
                         <*> pure UserBasedSecurityModel
                         <*> arbitrary
instance Arbitrary Flag where
    arbitrary = Flag <$> arbitrary <*> oneof [ pure NoAuthNoPriv, pure AuthNoPriv, pure AuthPriv ]

instance Arbitrary SecurityParameter where
    arbitrary = SecurityParameter <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ByteString where
    arbitrary = do
        l <- choose (0, 300)
        pack . take l <$> infiniteList

instance Arbitrary Value where
    arbitrary =
        oneof [ Integer <$> arbitrary
              , BitString <$> arbitrary
              , OctetString <$> arbitrary
              , pure Null
              , IpAddress <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
              , Counter32 <$> arbitrary
              , Gauge32 <$> arbitrary
              , TimeTicks <$> arbitrary
              , Opaque <$> arbitrary
              , NsapAddress <$> arbitrary
              , Counter64 <$> arbitrary
              , UInteger32 . abs <$> arbitrary
              , pure NoSuchInstance
              , pure NoSuchObject
              , pure EndOfMibView
              , OI <$> arbitrary
              ]

instance Arbitrary Request where
    arbitrary =
        oneof [ GetRequest <$> rid' <*> es' <*> ei'
              , GetNextRequest <$> rid' <*> es' <*> ei'
              , GetResponse <$> rid' <*> es' <*> ei'
              , SetRequest <$> rid' <*> es' <*> ei'
              , GetBulk <$> rid' <*> es' <*> ei'
              , Inform <$> rid' <*> es' <*> ei'
              , V2Trap <$> rid' <*> es' <*> ei'
              , Report <$> rid' <*> es' <*> ei'
              ]
      where
        rid' = RequestId <$> arbitrary
        es'  = ErrorStatus <$> arbitrary
        ei'  = ErrorIndex <$> arbitrary

instance Arbitrary ContextEngineID where
    arbitrary = ContextEngineID <$> arbitrary

instance Arbitrary ContextName where
    arbitrary = ContextName <$> arbitrary

instance Arbitrary Suite where
    arbitrary = Suite <$> listOfCoupla
      where
      listOfCoupla = listOf coupla
      coupla = Coupla <$> arbitrary <*> arbitrary

instance Arbitrary (PDU V2) where
    arbitrary = PDU <$> arbitrary <*> arbitrary

instance Arbitrary (PDU V3) where
    arbitrary = oneof [ ScopedPDU <$> arbitrary <*> arbitrary <*> arbitrary
                      , CryptedPDU <$> arbitrary
                      ]

instance Arbitrary Packet where
    arbitrary = oneof [ V2Packet Version1 <$> arbitrary <*> arbitrary
                      , V2Packet Version2 <$> arbitrary <*> arbitrary
                      , V3Packet Version3 <$> arbitrary <*> arbitrary
                      ]

