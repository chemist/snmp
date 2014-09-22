{-# LANGUAGE OverloadedStrings #-}
module Main where

import Data.ByteString (ByteString)
import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)
import qualified Data.ByteString as B
import Control.Applicative
import Data.Maybe
import Data.ASN1.Types
import Debug.Trace
import Prelude hiding (writeFile, readFile)
import Network.Protocol.Snmp
import Data.Word
import Data.Bits

root :: [Integer]
root = [1,3,6,1,2,1,2,2,1,2]

eth0 = [1,3,6,1,2,1,2,2,1,2, 1]

snmpServer :: HostName
snmpServer = "salt"

tabl = [31,1,1,1,1]

community = Community "helloall"
version = Version2


getRequest :: [Integer] -> IO ()
getRequest oid = withSocketsDo $ do
    serverAddress <- head <$> getAddrInfo (Just defaultHints) (Just snmpServer) (Just "161")
    sock <- socket (addrFamily serverAddress) Datagram defaultProtocol
    connect sock (addrAddress serverAddress)
    sendAll sock $ get agent version community 1 oid
    print =<< (result agent <$> recv sock 1500) -- cant be bigger without getting fragmented (see MTU)
    sendAll sock $ bulk agent version community 1 50 oid
    print =<< (result agent <$> recv sock 1500) -- cant be bigger without getting fragmented (see MTU)

main = mapM_ (\x -> (getRequest $ root ++ [x])) [1 .. 9]

a :: ByteString
a = "\NUL\152\150\128" -- 10000000 :: Integer

-- copy paste from asn1-encoding

packInteger :: Integer -> ByteString
packInteger = B.pack . bytesOfInt 

unpackInteger :: ByteString -> Either String Integer
unpackInteger = getIntegerRaw "Integer"

bytesOfInt :: Integer -> [Word8]
bytesOfInt i
  | i > 0      = if testBit (head uints) 7 then 0 : uints else uints
  | i == 0     = [0]
  | otherwise  = if testBit (head nints) 7 then nints else 0xff : nints
      where
      uints = bytesOfUInt (abs i)
      nints = reverse $ plusOne $ reverse $ map complement $ uints
      plusOne []     = [1]
      plusOne (x:xs) = if x == 0xff then 0 : plusOne xs else (x+1) : xs


--bytesOfUInt i = B.unfoldr (\x -> if x == 0 then Nothing else Just (fromIntegral (x .&. 0xff), x `shiftR` 8)) i
bytesOfUInt :: Integer -> [Word8]
bytesOfUInt x = reverse (list x)
  where list i = if i <= 0xff then [fromIntegral i] else (fromIntegral i .&. 0xff) : list (i `shiftR` 8)

{- | According to X.690 section 8.4 integer and enumerated values should be encoded the same way. -}
getIntegerRaw :: String -> ByteString -> Either String Integer
getIntegerRaw typestr s
    | B.length s == 0 = Left $ typestr ++ ": null encoding"
    | B.length s == 1 = Right $ snd $ intOfBytes s
    | otherwise       =
        if (v1 == 0xff && testBit v2 7) || (v1 == 0x0 && (not $ testBit v2 7))
            then Left $ typestr ++ ": not shortest encoding"
            else Right $ snd $ intOfBytes s
    where
        v1 = s `B.index` 0
        v2 = s `B.index` 1

{- | intOfBytes returns the number of bytes in the list and
the represented integer by a two's completement list of bytes -}
intOfBytes :: ByteString -> (Int, Integer)
intOfBytes b
    | B.length b == 0   = (0, 0)
    | otherwise         = (len, if isNeg then -(maxIntLen - v + 1) else v)
    where
        (len, v)  = uintOfBytes b
        maxIntLen = 2 ^ (8 * len) - 1
        isNeg     = testBit (B.head b) 7

{- | uintOfBytes returns the number of bytes and the unsigned integer represented by the bytes -}
uintOfBytes :: ByteString -> (Int, Integer)
uintOfBytes b = (B.length b, B.foldl (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0 b)




