{-# LANGUAGE FlexibleInstances #-}
module Main where

import Test.QuickCheck                      
import Test.QuickCheck.Gen (oneof)
import Test.Framework                       (defaultMain, testGroup, Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Network.Protocol.Snmp
import Data.ByteString (pack, ByteString)
import Data.Serialize

main :: IO ()
main = defaultMain tests

tests :: [Test]
tests = [ testGroup "encode decode" 
          [ testProperty "value" prop_Value 
          ] 
        ]
    
prop_Value :: Value -> Bool
prop_Value xs = Right xs == decode (encode xs)

instance Arbitrary Version where
    arbitrary = oneof [ pure Version1, pure Version2, pure Version3 ]

instance Arbitrary (Header V2) where
    arbitrary = V2Header . Community <$> arbitrary

instance Arbitrary (Header V3) where
    arbitrary = V3Header <$> (ID <$> arbitrary) 
                         <*> (MaxSize <$> arbitrary)
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
              , Uinteger32 . abs <$> arbitrary
              , pure NoSuchInstance
              , pure NoSuchObject
              , pure EndOfMibView
              , OI <$> oilist
              ]
        where
        oilist = do
            a <- choose (0,2)
            b <- choose (0,39)
            s <- choose (0,30)
            l <- take s <$> infiniteList
            return $ a : b : l

