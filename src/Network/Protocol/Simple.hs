{-# LANGUAGE OverloadedStrings #-}
module Network.Protocol.Simple 
( SnmpType(..)
, OID(..)
)
where


import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word
import Data.Bits
import Data.ASN1.Types
import Data.ASN1.Parse
import Control.Applicative
import Data.Time

data SnmpType = Simple ASN1
              | Zero
              | Integer Integer
              | String ByteString
              | IpAddress Word8 Word8 Word8 Word8
              | Counter32 Integer
              | Gaude32 Integer
              | TimeTicks Integer
              | Opaque ByteString
              | Counter64 Integer
              | ZeroDotZero
              | NoSuchInstance
              | NoSuchObject
              | EndOfMibView
              deriving (Show, Eq)

instance ASN1Object SnmpType where
    toASN1 NoSuchObject xs = Other Context 0 "" : xs
    toASN1 NoSuchInstance xs = Other Context 1 "" : xs
    toASN1 EndOfMibView xs = Other Context 2 "" : xs
    toASN1 (Simple x) xs = x : xs
    toASN1 Zero xs = Null : xs
    toASN1 ZeroDotZero xs = OID [0,0] : xs
    toASN1 (Integer x) xs = IntVal x : xs
    toASN1 (String x) xs = OctetString x : xs
    toASN1 (IpAddress a1 a2 a3 a4) xs = Other Application 0 (B.pack [a1, a2, a3, a4]) : xs
    toASN1 (Counter32 x) xs = Other Application 1 (packInteger x) : xs
    toASN1 (Gaude32 x) xs = Other Application 2 (packInteger x) : xs
    toASN1 (TimeTicks x) xs = Other Application 3 (packInteger x) : xs
    toASN1 (Opaque x) xs = Other Application 4 x : xs
    toASN1 (Counter64 x) xs = Other Application 6 (packInteger x) : xs
    fromASN1 asn = flip runParseASN1State asn (unp =<< getNext)
      where
      unp (Other Context 0 "") = return NoSuchObject
      unp (Other Context 1 "") = return NoSuchInstance
      unp (Other Context 2 "") = return EndOfMibView
      unp Null = return Zero
      unp (OID [0,0]) = return ZeroDotZero
      unp (IntVal x) = return $ Integer x
      unp (OctetString x) = return $ String x
      unp (Other Application 0 y) = let [a1, a2, a3, a4] = B.unpack y
                                    in return $ IpAddress a1 a2 a3 a4
      unp (Other Application 1 y) = case (unpackInteger y) of
                                         Right z -> return $ Counter32 z
                                         Left e -> error e
      unp (Other Application 2 y) = case (unpackInteger y) of
                                         Right z -> return $ Gaude32 z
                                         Left e -> error e
      unp (Other Application 3 y) = case (unpackInteger y) of
                                         Right z -> return $ TimeTicks z
                                         Left e -> error e
      unp (Other Application 4 y) = return $ Opaque y
      unp (Other Application 6 y) = case (unpackInteger y) of
                                         Right z -> return $ Counter64 z
                                         Left e -> error e
      unp x = return . Simple $ x

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




