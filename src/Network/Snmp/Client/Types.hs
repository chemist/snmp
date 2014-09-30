{-# LANGUAGE OverloadedStrings #-}
module Network.Snmp.Client.Types where

import Network.Protocol.Snmp
import Data.ByteString (ByteString)


type Hostname = String
type Port = String
type Login = ByteString
type Password = ByteString

data Config = ConfigV2
  { hostname :: Hostname
  , port :: Port
  , timeout :: Int
  , community :: Community
  }         | ConfigV3
  { hostname :: Hostname
  , port :: Port
  , timeout :: Int
  , login :: Login
  , password :: Password
  }
  deriving (Show, Eq)

sec :: Int -> Int
sec = (* 1000000)

data Client = Client 
  { get :: OIDS -> IO Suite
  , bulkget :: OIDS -> IO Suite 
  , getnext :: OIDS -> IO Suite
  , walk :: OIDS -> IO Suite
  , bulkwalk :: OIDS -> IO Suite
  , set :: Suite -> IO Suite
  , close :: IO ()
  }

defConfig Version1 = ConfigV2 "localhost" "161" (sec 5) (Community "public") 
defConfig Version2 = ConfigV2 "localhost" "161" (sec 5) (Community "public")
defConfig Version3 = ConfigV3 "localhost" "161" (sec 5) "guest" "readonly"

