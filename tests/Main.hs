module Main where

import Test.QuickCheck                      (Gen, Arbitrary(..), choose)
import Test.Framework                       (defaultMain, testGroup, Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Network.Protocol.Snmp

main :: IO ()
main = defaultMain tests

tests :: [Test]
tests =
    [ ]


