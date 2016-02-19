{-# LANGUAGE PackageImports #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Criterion.Main
import Network.Protocol.Snmp
import Data.Serialize 
-- import qualified "cryptohash" Crypto.Hash.MD5      as MD5
-- import qualified "cryptohash" Crypto.Hash.SHA1     as SHA1
-- import Data.ByteString (ByteString)
-- import qualified Data.ByteString.Lazy as L


main :: IO ()
main = defaultMain
  [ bgroup "new"
    [ bench "pack unpack version 1" $ whnf packUnpack Version1
    , bench "pack unpack version 2" $ whnf packUnpack Version2
    , bench "pack unpack version 3" $ whnf packUnpack Version3
    ]
--  , bgroup "hash"
--    [ bench "cryptohash md5 strict" $ whnf MD5.hash str
--    , bench "cryptohash md5 lazy" $ whnf MD5.hashlazy lstr
--    , bench "cryptohash sha1 strict" $ whnf SHA1.hash str
--    , bench "cryptohash sha1 lazy" $ whnf SHA1.hashlazy lstr
--    , bench "cryptonite md5 strict" $ whnf chash str
--    , bench "cryptonite md5 lazy" $ whnf clhash lstr
--    , bench "cryptonite sha1 strict" $ whnf cshash str
--    , bench "cryptonite sha1 lazy" $ whnf cslhash lstr
--    ]
  ]

packUnpack :: Version -> Either String Packet
packUnpack v = decode (encode (initial v :: Packet))

-- chash :: ByteString -> ByteString
-- chash = hash MD5
-- 
-- cshash :: ByteString -> ByteString
-- cshash = hash SHA
-- 
-- clhash :: L.ByteString -> ByteString
-- clhash = hashlazy MD5
-- 
-- cslhash :: L.ByteString -> ByteString
-- cslhash = hashlazy SHA
-- 
-- str :: ByteString
-- str = "asdfasdfasdfasdgasdlgkjasdfoasjpojvpajsdpofijaspoifdjapsodijfpaosdijfpoasjdfpoiasdfjasoidjfpasfij"
-- 
-- lstr :: L.ByteString
-- lstr = "asdfasdfasdfasdgasdlgkjasdfoasjpojvpajsdpofijaspoifdjapsodijfpaosdijfpoasjdfpoiasdfjasoidjfpasfij"

