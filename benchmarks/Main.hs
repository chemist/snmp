module Main where

import Criterion.Main
import Network.Protocol.Snmp
import Data.Serialize 


main :: IO ()
main = defaultMain
  [ bgroup "new"
    [ bench "pack unpack version 1" $ whnf packUnpack Version1
    , bench "pack unpack version 2" $ whnf packUnpack Version2
    , bench "pack unpack version 3" $ whnf packUnpack Version3
    ]
  ]

packUnpack :: Version -> Either String Packet
packUnpack v = decode (encode (initial v :: Packet))
