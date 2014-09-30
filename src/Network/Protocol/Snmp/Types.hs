{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.Protocol.Snmp.Types 
( Value(..)
, OID(..)
, Pack(..)
, PDU(..)
, Suite(..)
, Coupla(..)
, RequestId
, Request(..)
, ClientException(..) 
, Version(..)
, Header(..)
, SnmpPacket(..)
)
where


import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word
import Data.Bits
import Data.ASN1.Types
import Data.ASN1.Parse
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Control.Applicative
import Data.Time
import Data.Monoid
import Control.Exception
import Data.Typeable
import Debug.Trace 

data Value = Simple ASN1
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

instance ASN1Object Value where
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

data Version = Version1
             | Version2 
             | Version3
             deriving (Eq, Show)

data Header a = Header Version a deriving (Eq)

instance Show a => Show (Header a) where
    show (Header v a) = "\n  version: " ++ show v ++ "\n  " ++ show a

instance ASN1Object a => ASN1Object (Header a) where
    toASN1 (Header Version1 x) xs = IntVal 0 : toASN1 x xs
    toASN1 (Header Version2 x) xs = IntVal 1 : toASN1 x xs
    toASN1 (Header Version3 x) xs = IntVal 3 : toASN1 x xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        case x of
             0 -> Header Version1 <$> getObject
             1 -> Header Version2 <$> getObject
             3 -> Header Version3 <$> getObject

data SnmpPacket a b = SnmpPacket a b deriving (Eq)

instance (Show a, Show b) => Show (SnmpPacket a b) where
    show (SnmpPacket a b) = "snmp packet: \n  header: " ++ show a ++ "\n  pdu: " ++ show b

instance (ASN1Object a, ASN1Object b, Show b, Show a) => ASN1Object (SnmpPacket a b) where
    toASN1 (SnmpPacket header pdu) _ = 
      Start Sequence : ( toASN1 header ( toASN1 pdu [End Sequence]))

    fromASN1 asn = flip runParseASN1State asn $ onNextContainer Sequence $ do
        header <- getObject
        pdu <- getObject
        return $ SnmpPacket header pdu 

class Pack a where
    encode :: a -> ByteString
    decode :: ByteString -> a

instance (ASN1Object a, ASN1Object b, Show b, Show a) => Pack (SnmpPacket a b) where
    encode s = encodeASN1' DER $ toASN1 s []
    decode = toB 

toB :: (ASN1Object a, ASN1Object b, Show b, Show a) => ByteString -> SnmpPacket a b
toB bs = let a = fromASN1 <$> decodeASN1' DER bs
         in case a of
                 Right (Right (r, _)) -> r
                 _ -> error "bad packet"

type RequestId = Integer
type ErrorStatus = Integer
type ErrorIndex = Integer

data Request = GetRequest RequestId ErrorStatus ErrorIndex 
             | GetNextRequest RequestId ErrorStatus ErrorIndex 
             | GetResponse RequestId ErrorStatus ErrorIndex  
             | SetRequest RequestId ErrorStatus ErrorIndex 
             | GetBulk RequestId ErrorStatus ErrorIndex 
             | Inform
             | V2Trap
             | Report RequestId ErrorStatus ErrorIndex
             deriving (Show, Eq)

data PDU = PDU Request Suite deriving (Show, Eq)

data Coupla = Coupla OID Value deriving (Eq)

newtype Suite = Suite [Coupla] deriving (Eq, Monoid)

instance Show Coupla where
    show (Coupla o v) = oidToString o ++ " = " ++ show v

instance Show Suite where
    show (Suite xs) = unlines $ map show xs

oidToString :: OID -> String
oidToString xs = foldr1 (\x y -> x ++ "." ++ y) $ map show xs

instance ASN1Object PDU where
    toASN1 (PDU (GetRequest rid _ _    ) sd) xs = (Start $ Container Context 0):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 0)] ++ xs
    toASN1 (PDU (GetNextRequest rid _ _) sd) xs = (Start $ Container Context 1):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 1)] ++ xs
    toASN1 (PDU (GetResponse rid es ei ) sd) xs = (Start $ Container Context 2):IntVal rid : IntVal es : IntVal ei: Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 2)] ++ xs
    toASN1 (PDU (SetRequest rid _ _    ) sd) xs = (Start $ Container Context 3):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 3)] ++ xs
    toASN1 (PDU (GetBulk rid es ei     ) sd) xs = (Start $ Container Context 5):IntVal rid : IntVal es : IntVal ei: Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 4)] ++ xs
    toASN1 (PDU (Report rid es ei      ) sd) xs = (Start $ Container Context 8):IntVal rid : IntVal es : IntVal ei: Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 8)] ++ xs

    fromASN1 asn = flip runParseASN1State asn $ do
        Start container <- getNext
        IntVal rid <- getNext
        IntVal es <- getNext
        IntVal ei <- getNext
        x <- getNextContainer Sequence
        End container <- getNext
        let psuite = fromASN1 x
        case (container, psuite) of
             (Container Context 0, Right (suite, _)) -> return $ PDU (GetRequest     rid es ei) suite
             (Container Context 1, Right (suite, _)) -> return $ PDU (GetNextRequest rid es ei) suite
             (Container Context 2, Right (suite, _)) -> return $ PDU (GetResponse    rid es ei) suite
             (Container Context 3, Right (suite, _)) -> return $ PDU (SetRequest     rid es ei) suite
             (Container Context 5, Right (suite, _)) -> return $ PDU (GetBulk        rid es ei) suite
             (Container Context 8, Right (suite, _)) -> return $ PDU (Report         rid es ei) suite
             e -> error $ "cant parse PDU " ++ show e

instance ASN1Object Suite where
    toASN1 (Suite xs) ys = foldr toA [] xs ++ ys
      where 
      toA ::Coupla -> [ASN1] -> [ASN1]
      toA (Coupla o v) zs = [Start Sequence , OID o] ++ toASN1 v (End Sequence : zs)
    fromASN1 asn = flip runParseASN1State asn $ do
        xs <- getMany $ do
               Start Sequence <- getNext
               OID x <- getNext
               v <-  getObject
               End Sequence <- getNext
               return $ Coupla x v
        return $ Suite xs

data ClientException = TimeoutException 
                     | ServerException Integer
                     deriving (Typeable, Eq)

instance Show ClientException where
    show TimeoutException = "Timeout exception"
    show (ServerException 1) = "tooBig"
    show (ServerException 2) = "noSuchName"
    show (ServerException 3) = "badValue"
    show (ServerException 4) = "readOnly"
    show (ServerException 5) = "genErr"
    show (ServerException 6) = "noAccess"
    show (ServerException 7) = "wrongType"
    show (ServerException 8) = "wrongLength"
    show (ServerException 9) = "wrongEncoding"
    show (ServerException 10) = "wrongValue"
    show (ServerException 11) = "noCreation"
    show (ServerException 12) = "inconsistentValue"
    show (ServerException 13) = "resourceUnavailable"
    show (ServerException 14) = "commitFailed"
    show (ServerException 15) = "undoFailed"
    show (ServerException 16) = "authorizationError"
    show (ServerException 17) = "notWritable"
    show (ServerException 18) = "inconsistentName"
    show (ServerException 80) = "General IO failure occured on the set request"
    show (ServerException 81) = "General SNMP timeout occured"
    show (ServerException x) = "Exception " ++ show x

instance Exception ClientException

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




