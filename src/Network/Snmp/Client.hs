{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Network.Snmp.Client 
( Client
, client
, Hostname
, Port
, oidFromBS
, Community(..)
, SnmpVersion(..)
, get
, bulkget
, getnext
, close
, Config(..)
, defConfig
)
where

import Data.ByteString (ByteString)
import Network.Socket hiding (recv, socket, close)
import qualified Network.Socket as NS
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Control.Applicative
import Data.Maybe
import Network.Protocol.Snmp
import Network.Protocol.Simple

oidFromBS :: ByteString -> [Integer]
oidFromBS xs = catMaybes $ map (\x -> fst <$> C.readInteger x) $ C.splitWith (== '.') xs

type Hostname = String
type Port = String

makeSocket :: Hostname -> Port -> IO Socket
makeSocket hostname port = do
    serverAddress <- head <$> getAddrInfo (Just defaultHints) (Just hostname) (Just port)
    sock <- NS.socket (addrFamily serverAddress) Datagram defaultProtocol
    connect sock (addrAddress serverAddress)
    return sock

type OIDS = [OID]

data Config = Config 
  { hostname :: Hostname
  , port :: Port
  , community :: Community
  , version :: SnmpVersion
  } deriving (Show, Eq)

defConfig :: Config
defConfig = Config "localhost" "161" (Community "public") Version2

data Client = Client 
  { get :: OIDS -> IO SnmpData
  , bulkget :: OIDS -> IO SnmpData 
  , getnext :: OIDS -> IO SnmpData
  , close :: IO ()
  }

client :: Config -> IO Client
client Config{..} = do
    socket <- makeSocket hostname port 
    return $ Client 
        { get = \oids -> withSocketsDo $ do
            sendAll socket $ encode (SnmpPacket version community (PDU (GetRequest 1 0 0) (SnmpData $ map (\x -> (x, Zero)) oids)))
            SnmpPacket _ _ (PDU (GetResponse 1 e ie) d) <- decode <$> recv socket 1500
            return d
        , bulkget = \oids -> withSocketsDo $ do
            sendAll socket $ encode (SnmpPacket version community (PDU (GetBulk 1 0 10) (SnmpData $ map (\x -> (x, Zero)) oids)))
            SnmpPacket _ _ (PDU (GetResponse 1 e ie) d) <- decode <$> recv socket 1500
            return d
        , getnext = \oids -> withSocketsDo $ do
            sendAll socket $ encode (SnmpPacket version community (PDU (GetNextRequest 1 0 0) (SnmpData $ map (\x -> (x, Zero)) oids)))
            SnmpPacket _ _ (PDU (GetResponse 1 e ei) d) <- decode <$> recv socket 1500
            return d
        , close = NS.close socket
        } 

