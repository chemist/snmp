{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Criterion.Main
import           Network.Protocol.Snmp

main :: IO ()
main = defaultMain
  [ bgroup "packet pack/unpack"
    [ bench "version 1" $ whnf packUnpackPacket Version1
    , bench "version 2" $ whnf packUnpackPacket Version2
    , bench "version 3" $ whnf packUnpackPacket Version3
    ]
  , bgroup "value pack/unpack"
    [ bench "integer" $ whnf packUnpackValue (Integer 65535)
    , bench "long oid" $ whnf packUnpackValue (OI $ Oid [1..65535])
    , bench "OctetString" $ whnf packUnpackValue (OctetString "some test string")
    ]
  , bgroup "encryption: password to key"
    [ bench "MD5" $ whnf pToK MD5
    , bench "SHA" $ whnf pToK SHA
    ]
  ]

packUnpackPacket :: Version -> Either String Packet
packUnpackPacket v = decode (encode (initial v :: Packet))

packUnpackValue :: Value -> Either String Value
packUnpackValue = decode . encode

pToK :: AuthType -> Key
pToK at = passwordToKey at (Password "mytestpassword") (EngineID "abcdefghi")

