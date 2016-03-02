{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Criterion.Main
import           Network.Protocol.Snmp

main :: IO ()
main = defaultMain
  [ bgroup "packet pack/unpack"
    [ bench "pack unpack version 1" $ whnf packUnpackPacket Version1
    , bench "pack unpack version 2" $ whnf packUnpackPacket Version2
    , bench "pack unpack version 3" $ whnf packUnpackPacket Version3
    ]
  , bgroup "value pack/unpack"
    [ bench "pack integer" $ whnf packUnpackValue (Integer 65535)
    , bench "pack long oid" $ whnf packUnpackValue (OI $ Oid [1..65535])
    , bench "pack OctetString" $ whnf packUnpackValue (OctetString "some test string")
    ]
  ]

packUnpackPacket :: Version -> Either String Packet
packUnpackPacket v = decode (encode (initial v :: Packet))

packUnpackValue :: Value -> Either String Value
packUnpackValue = decode . encode

