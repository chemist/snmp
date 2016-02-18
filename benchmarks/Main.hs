module Main where

import           Criterion.Main
import           Data.ByteString       (ByteString)
import           Data.Serialize
import           Network.Protocol.Snmp


main :: IO ()
main = defaultMain
  [ bgroup "new"
    [ bench "pack unpack version 1" $ whnf packUnpack Version1
    , bench "pack unpack version 2" $ whnf packUnpack Version2
    , bench "pack unpack version 3" $ whnf packUnpack Version3
    , bench "pack version 1" $ whnf pack Version1
    , bench "pack version 2" $ whnf pack Version2
    , bench "pack version 3" $ whnf pack Version3
    ]
  ]

pack :: Version -> ByteString
pack v = encode (initial v :: Packet)

packUnpack :: Version -> Either String Packet
packUnpack v = decode (encode (initial v :: Packet))
