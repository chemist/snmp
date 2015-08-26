{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
module Network.Snmp.Client.Types where

import Network.Protocol.Snmp
import Data.ByteString (ByteString)


type Hostname = String
type Port = String
type Login = ByteString


data Config = ConfigV1 
  { hostname :: Hostname
  , port :: Port
  , timeout :: Int
  , community :: Community
  }         | ConfigV2
  { hostname :: Hostname
  , port :: Port
  , timeout :: Int
  , community :: Community
  }         | ConfigV3
  { hostname :: Hostname
  , port :: Port
  , timeout :: Int
  , securityName :: Login
  , authPass :: Password
  , privPass :: Password
  , securityLevel :: PrivAuth
  , context :: ByteString
  , authType :: AuthType
  , privType :: PrivType
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

instance Construct (Version -> Config) where
    initial Version1 = ConfigV1 "localhost" "161" (sec 5) (Community "public") 
    initial Version2 = ConfigV2 "localhost" "161" (sec 5) (Community "public")
    initial Version3 = ConfigV3 "localhost" "161" (sec 5) "guest" "" "" AuthNoPriv "" MD5 DES


