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
  , sequrityName :: Login
  , authPass :: Password
  , privPass :: Password
  , sequrityLevel :: PrivAuth
  , context :: ByteString
  , authType :: AuthType
  , privType :: PrivType
  }
  deriving (Show, Eq)

data AuthType = MD5 | SHA deriving (Show, Eq)
data PrivType = DES | AES deriving (Show, Eq)

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
defConfig Version3 = ConfigV3 
  { hostname = "localhost" 
  , port = "161" 
  , timeout = (sec 5) 
  , sequrityName = "guest" 
  , authPass = "readonly"
  , privPass = "readonly"
  , sequrityLevel = AuthNoPriv
  , context = ""
  , authType = MD5
  , privType = DES
  }


