{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.Protocol.Snmp.Types 
( Value(..)
, OID
, Pack(..)
, PDU(..)
, Suite(..)
, Coupla(..)
, RequestId
, Request(..)
, ClientException(..) 
, Version(..)
, Header(..)
, Packet(..)
, Community(..)
, ID(..)
, MaxSize(..)
, Flag(..)
, SecurityModel(..)
, SecurityParameter(..)
, Reportable
, PrivAuth(..)
, VersionedPDU(..)
, ContextEngineID(..)
, ContextName(..)
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

instance Monoid Version where
    mempty = Version1
    _ `mappend` x = x

newtype Community = Community ByteString deriving (Show, Eq)

instance Monoid Community where
    mempty = Community ""
    Community x `mappend` Community y = Community (x <> y)

instance ASN1Object Community where
    toASN1 (Community x) xs = OctetString x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        OctetString x <- getNext
        return $ Community x

-- Message Identifier (like RequestId in PDU)
newtype ID = ID Integer deriving (Show, Eq)

deriving instance Monoid ID

-- Message max size must be > 484
newtype MaxSize = MaxSize Integer deriving (Show, Eq)

deriving instance Monoid MaxSize

data PrivAuth = NoAuthNoPriv | AuthNoPriv | AuthPriv deriving (Show, Eq)

instance Monoid PrivAuth where
    mempty = NoAuthNoPriv
    mappend _ x = x

type Reportable = Bool

data Flag = Flag Reportable PrivAuth  deriving (Show, Eq)

instance Monoid Flag where
    mempty = Flag False mempty
    mappend (Flag True x) (Flag _ y) = Flag True (x <> y)
    mappend (Flag _ x) (Flag True y) = Flag True (x <> y)
    mappend (Flag False x) (Flag False y) = Flag True (x <> y)

data SecurityModel = UserBasedSecurityModel deriving (Show, Eq)

instance Monoid SecurityModel where
    mempty = UserBasedSecurityModel
    mappend _ _ = UserBasedSecurityModel

data SecurityParameter = SecurityParameter 
  { authoritiveEngineId :: ByteString
  , authoritiveEngineBoots :: Integer
  , authoritiveEngineTime :: Integer
  , userName :: ByteString
  , authenticationParameters :: ByteString
  , privacyParameters :: ByteString
  }
  deriving (Eq)

instance Show SecurityParameter where
    show msg = "SecurityParameter:\n\t\tAuthoritiveEngineId: " 
       ++ show (authoritiveEngineId msg )
       ++ "\n\t\tAuthoritiveEngineBoots: " ++ show (authoritiveEngineBoots msg )
       ++ "\n\t\tAuthoritiveEngineTime: " ++ show (authoritiveEngineTime msg )
       ++ "\n\t\tUserName: " ++ show (userName msg )
       ++ "\n\t\tAuthenticationParameters: " ++ show (authenticationParameters msg )
       ++ "\n\t\tPrivacyParameters: " ++ show (privacyParameters msg )


instance Monoid Integer where
    mempty = 0
    mappend = (+)

instance Monoid SecurityParameter where
    mempty = SecurityParameter "" 0 0 "" "" ""
    mappend (SecurityParameter a0 b0 c0 d0 e0 f0) 
            (SecurityParameter a1 b1 c1 d1 e1 f1) 
            = SecurityParameter (a0 <> a1) (b0 <> b1) (c0 <> c1) (d0 <> d1) (e0 <> e1) (f0 <> f1)

data Header = HeaderV2 
  { version :: Version 
  , community  :: Community
  }         | HeaderV3 
  { version :: Version
  , iD :: ID 
  , maXSize :: MaxSize
  , flag :: Flag 
  , securityModel :: SecurityModel 
  , securityParameter :: SecurityParameter
  } deriving (Eq)

instance Show Header where
    show hd | version hd == Version3 = "\n  version: " ++ show (version hd) ++ "\n  " 
                                                      ++ show (iD hd)  ++ "\n  "
                                                      ++ show (maXSize hd) ++ "\n  "
                                                      ++ show (flag hd) ++ "\n  "
                                                      ++ show (securityModel hd) ++ "\n  "
                                                      ++ show (securityParameter hd) 

instance ASN1Object ID where
    toASN1 (ID x) xs = IntVal x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        return $ ID x

instance ASN1Object MaxSize where
    toASN1 (MaxSize x) xs = IntVal x : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        return $ MaxSize x

instance ASN1Object Flag where
    toASN1 (Flag r pa) xs = let zero = zeroBits :: Word8
                                reportable = if r then setBit zero 0 else zero
                                privauth = case pa of
                                                NoAuthNoPriv -> zero
                                                AuthNoPriv -> setBit zero 2
                                                AuthPriv -> setBit zero 1 .|. setBit zero 2
                                flag = reportable .|. privauth
                            in OctetString (B.pack [flag]) : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        OctetString x <- getNext
        let [w] = B.unpack x
        return $ case (testBit w 1, testBit w 2) of
                      (True, True) -> Flag (testBit w 0) AuthPriv
                      (False, False) -> Flag (testBit w 0) NoAuthNoPriv
                      (False, True) -> Flag (testBit w 0) AuthNoPriv
                      _ -> error "bad flag"


instance ASN1Object SecurityModel where
    toASN1 UserBasedSecurityModel xs = IntVal 3 : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        case x of
             3 -> return UserBasedSecurityModel
             _ -> error "other security model"

instance ASN1Object SecurityParameter where
    toASN1 SecurityParameter{..} xs = OctetString (encodeASN1' DER
      [ Start Sequence
      ,   OctetString authoritiveEngineId 
      ,   IntVal authoritiveEngineBoots 
      ,   IntVal authoritiveEngineTime 
      ,   OctetString userName 
      ,   OctetString authenticationParameters 
      ,   OctetString privacyParameters 
      , End Sequence
      ]) : xs
    fromASN1 asn = flip runParseASN1State asn $ do
        OctetString packed <- getNext
        let r = case decodeASN1' DER packed of
             Left e -> error $ "cant unpack msgSecurity parameter " ++ show e
             Right asn' -> parseMsgSecurityParameter asn'
        case r of
             Left e -> error $ "cant parse msgSecurity parameter" ++ show e
             Right r -> return r

parseMsgSecurityParameter :: [ASN1] -> Either String SecurityParameter
parseMsgSecurityParameter asn = flip runParseASN1 asn $ do
     Start Sequence <- getNext
     OctetString msgAuthoritiveEngineId <- getNext
     IntVal msgAuthoritiveEngineBoots <- getNext
     IntVal msgAuthoritiveEngineTime <- getNext
     OctetString msgUserName <- getNext
     OctetString msgAuthenticationParameters <- getNext
     OctetString msgPrivacyParameters <- getNext
     End Sequence <- getNext
     return $ SecurityParameter msgAuthoritiveEngineId msgAuthoritiveEngineBoots msgAuthoritiveEngineTime msgUserName msgAuthenticationParameters msgPrivacyParameters 


instance ASN1Object Header where
    toASN1 (HeaderV2 Version3 _) _ = error "bad header data"
    toASN1 (HeaderV2 Version1 x) xs = IntVal 0 : toASN1 x xs
    toASN1 (HeaderV2 Version2 x) xs = IntVal 1 : toASN1 x xs
    toASN1 HeaderV3{..} xs = IntVal 3 : ( 
        Start Sequence : toASN1 iD (toASN1 maXSize (toASN1 flag (toASN1 securityModel [End Sequence])))) ++ toASN1 securityParameter xs
    fromASN1 asn = flip runParseASN1State asn $ do
        IntVal x <- getNext
        case x of
             0 -> HeaderV2 Version1 <$> getObject
             1 -> HeaderV2 Version2 <$> getObject
             3 -> getV3
             _ -> error "unknown version tag"
        where
          getV3 = do
              Start Sequence <- getNext
              i <- getObject
              ms <- getObject
              f <- getObject
              sm <- getObject
              End Sequence <- getNext
              sp <- getObject
              return $ HeaderV3 Version3 i ms f sm sp

data Packet = Packet 
  { header :: Header
  , body :: VersionedPDU
  } deriving (Eq)

newtype ContextEngineID = ContextEngineID ByteString deriving (Show, Eq)

deriving instance Monoid ContextEngineID

newtype ContextName = ContextName ByteString deriving (Show, Eq)

deriving instance Monoid ContextName

data VersionedPDU = SimplePDU
  { pdu :: PDU
  }               | ScopedPDU
  { contextEngineId :: ContextEngineID
  , contextName :: ContextName
  , pdu :: PDU
  } deriving (Eq, Show)

data PDU = PDU { request :: Request, suite :: Suite } deriving (Show, Eq)

instance ASN1Object VersionedPDU where
    toASN1 (SimplePDU (PDU (GetRequest rid _ _    ) sd)) xs = (Start $ Container Context 0):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 0)] ++ xs
    toASN1 (SimplePDU (PDU (GetNextRequest rid _ _) sd)) xs = (Start $ Container Context 1):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 1)] ++ xs
    toASN1 (SimplePDU (PDU (GetResponse rid es ei ) sd)) xs = (Start $ Container Context 2):IntVal rid : IntVal es : IntVal ei: Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 2)] ++ xs
    toASN1 (SimplePDU (PDU (SetRequest rid _ _    ) sd)) xs = (Start $ Container Context 3):IntVal rid : IntVal 0  : IntVal 0 : Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 3)] ++ xs
    toASN1 (SimplePDU (PDU (GetBulk rid es ei     ) sd)) xs = (Start $ Container Context 5):IntVal rid : IntVal es : IntVal ei: Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 4)] ++ xs
    toASN1 (SimplePDU (PDU (Report rid es ei      ) sd)) xs = (Start $ Container Context 8):IntVal rid : IntVal es : IntVal ei: Start Sequence : toASN1 sd [] ++ [ End Sequence, End (Container Context 8)] ++ xs
    toASN1 (ScopedPDU (ContextEngineID x) (ContextName y) pdu) xs = 
      [Start Sequence, OctetString x, OctetString y] ++ (toASN1 (SimplePDU pdu) (End Sequence :xs))
    fromASN1 asn = flip runParseASN1State asn $ do
        Start whatIs <- getNext
        case whatIs of
             Container Context n -> SimplePDU <$> simplePDU (Container Context n)
             Sequence -> do
                 OctetString x <- getNext
                 OctetString y <- getNext
                 Start s <- getNext
                 p <- simplePDU s
                 End Sequence <- getNext
                 return $ ScopedPDU (ContextEngineID x) (ContextName y) p
             _ -> error "bad VersionedPDU"

simplePDU :: ASN1ConstructionType -> ParseASN1 PDU
simplePDU (Container Context n) = do
    IntVal rid <- getNext
    IntVal es <- getNext
    IntVal ei <- getNext
    x <- getNextContainer Sequence 
    End (Container Context _) <- getNext
    let psuite = fromASN1 x
    case (n, psuite) of
         (0, Right (suite, _)) -> return $ PDU (GetRequest     rid es ei) suite
         (1, Right (suite, _)) -> return $ PDU (GetNextRequest rid es ei) suite
         (2, Right (suite, _)) -> return $ PDU (GetResponse    rid es ei) suite
         (3, Right (suite, _)) -> return $ PDU (SetRequest     rid es ei) suite
         (5, Right (suite, _)) -> return $ PDU (GetBulk        rid es ei) suite
         (8, Right (suite, _)) -> return $ PDU (Report         rid es ei) suite
         e -> error $ "cant parse PDU " ++ show e
simplePDU _ = error "bad PDU"

instance ASN1Object Packet where
    toASN1 Packet{..} _ = Start Sequence : toASN1 header (toASN1 body [End Sequence])
    fromASN1 asn = flip runParseASN1State asn $ onNextContainer Sequence $ do
        header <- getObject
        body <- getObject
        return $ Packet header body

instance Show Packet where
    show Packet{..} = "snmp packet: \n  header: " ++ show header ++ "\n  pdu: " ++ show body
  
class Pack a where
    encode :: a -> ByteString
    decode :: ByteString -> a

instance Pack Packet where
    encode s = encodeASN1' DER $ toASN1 s []
    decode = toB 

toB :: ByteString -> Packet 
toB bs = let a = fromASN1 <$> decodeASN1' DER bs
         in case a of
                 Right (Right (r, _)) -> r
                 _ -> error "bad packet"
                 --}

type RequestId = Integer
type ErrorStatus = Integer
type ErrorIndex = Integer

data Request = GetRequest     { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | GetNextRequest { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | GetResponse    { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | SetRequest     { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | GetBulk        { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | Inform         { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | V2Trap         { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             | Report         { rid :: RequestId, es :: ErrorStatus, ei :: ErrorIndex }
             deriving (Show, Eq)


instance Monoid PDU where
    mempty = PDU (GetRequest 0 0 0) mempty
    _ `mappend` PDU a1 b1 = PDU a1 b1

data Coupla = Coupla { _oid :: OID, _value :: Value } deriving (Eq)

newtype Suite = Suite [Coupla] deriving (Eq, Monoid)

instance Show Coupla where
    show (Coupla o v) = oidToString o ++ " = " ++ show v

instance Show Suite where
    show (Suite xs) = unlines $ map show xs

oidToString :: OID -> String
oidToString xs = foldr1 (\x y -> x ++ "." ++ y) $ map show xs

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

