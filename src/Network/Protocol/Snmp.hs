module Network.Protocol.Snmp where

import Data.ASN1.Parse
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Control.Applicative

data Request = GetRequest OID
             | GetNextRequest OID
             | GetResponse Integer Integer [(OID, [ASN1])]
             | SetRequest OID ASN1
             | GetBulk Integer Integer OID
             | Inform
             | V2Trap
             | Report
             deriving (Show, Eq)

instance Enum Request where
    fromEnum (GetRequest  _ ) = 0
    fromEnum (GetNextRequest _ ) = 1
    fromEnum (GetResponse _ _ _ ) = 2
    fromEnum (SetRequest _ _) = 3
    fromEnum (GetBulk _ _ _ ) = 5
    fromEnum (Inform        ) = 6
    fromEnum (V2Trap        ) = 7
    fromEnum (Report        ) = 8
    toEnum 0 = (GetRequest undefined  )
    toEnum 1 = (GetNextRequest undefined)
    toEnum 2 = (GetResponse undefined undefined undefined)
    toEnum 3 = (SetRequest undefined   undefined)
    toEnum 5 = (GetBulk undefined undefined   undefined )
    toEnum 6 = (Inform        )
    toEnum 7 = (V2Trap        )
    toEnum 8 = (Report        )
    toEnum _ = undefined

instance ASN1Object SnmpVersion where
    toASN1 Version2 xs = IntVal 0 : xs

instance ASN1Object Request where
    toASN1 (GetRequest _) xs = (Start $ Container Context 0) : xs

ee oid =  toASN1 Version2 $ toASN1 (GetRequest oid) []

data SnmpVersion = Version1
                 | Version2
                 deriving (Show, Enum, Eq, Ord)

type Community = ByteString
type RequestId = Integer

data Snmp = Snmp
  { version :: SnmpVersion
  , community :: Community
  , requestType :: Request
  , requestId :: RequestId
  } deriving (Show, Eq)

instance ASN1Object Snmp where
    toASN1 snmp = \x -> x ++   [ Start Sequence
                              , IntVal . fromIntegral . fromEnum $ version snmp           -- snmp verion 
                              , OctetString $ community snmp                              -- community string
                              , Start $ Container Context $ fromEnum $ requestType snmp   -- Request PDU
                              , IntVal $ requestId snmp                                   -- Request ID
                              , IntVal $ makeError snmp                                   -- error
                              , IntVal $ makeIndexError snmp                              -- error index
                              , Start Sequence                                      
                              , Start Sequence 
                              , OID $ oid snmp                                            -- oid
                              , snmpData snmp 
                              , End Sequence
                              , End Sequence
                              , End (Container Context $ fromEnum $ requestType snmp)
                              , End Sequence
                              ]
    fromASN1 asn = runParseASN1State snmpParser asn

class SnmpPack a where
    encode :: a -> ByteString
    decode :: ByteString -> a

instance SnmpPack Snmp where
    encode snmp = toStrict $ encodeASN1 DER $ toASN1 snmp []
    decode = toB 

toB :: ByteString -> Snmp
toB bs = let a = fromASN1 <$> decodeASN1 DER (fromStrict bs)
         in case a of
                 Right (Right (r, _)) -> r
                 _ -> error "bad packet"

oid :: Snmp -> OID
oid x = case requestType x of
             GetRequest y -> y
             GetNextRequest y -> y
             SetRequest y _ -> y
             GetBulk _ _ y -> y
             _ -> undefined

snmpParser :: ParseASN1 Snmp
snmpParser = onNextContainer Sequence  allParse

allParse :: ParseASN1 Snmp
allParse = do
    IntVal v <-  getNext 
    OctetString c <- getNext
    (rt, rid, xs) <- onNextContainer (Container Context (fromEnum $ GetResponse undefined undefined undefined)) parsePDU
    return $ Snmp (toEnum .fromIntegral $ v) c (rt xs) rid 

parsePDU :: ParseASN1 ([(OID, [ASN1])] -> Request, Integer, [(OID, [ASN1])])
parsePDU = do
    IntVal rid <- getNext
    IntVal e <- getNext
    IntVal ie <- getNext
    xs <- onNextContainer Sequence $ getMany $ onNextContainer Sequence $ do
        OID oid' <- getNext
        obj <- getMany $ getNext
        return $ (oid', obj)
    return (GetResponse e ie, rid, xs) 



makeError :: Snmp -> Integer
makeError snmp = case requestType snmp of
                      GetBulk x _ _ -> x
                      _ -> 0

makeIndexError :: Snmp -> Integer
makeIndexError snmp = case requestType snmp of
                           GetBulk _ x _ -> x
                           _ -> 0

snmpData :: Snmp -> ASN1
snmpData snmp = case requestType snmp of
                     SetRequest _ a -> a
                     _ -> Null


