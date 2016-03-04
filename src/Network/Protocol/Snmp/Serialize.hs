{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs             #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Network.Protocol.Snmp.Serialize
    (
    -- * encoding/decoding
      encode
    , decode

    , putVarEncodingIntegral
    , getVarEncodingIntegral

    , putValue
    , getValue

    , putOid
    , getOid
    ) where

import           Control.Monad
import           Data.Bits
import           Data.ByteString             (ByteString)
import qualified Data.ByteString             as B
import           Data.Int                    (Int32)
-- import           Data.List                   (foldl', unfoldr)
import           Data.Serialize
import           Data.Word                   (Word8)

import           Network.Protocol.Snmp.Types


type ErrorCode = Int

putLength :: Int -> Put
putLength = putSize . Size
{-# INLINE putLength #-}

getLength :: Get Int
getLength = do
    Size i <- getSize
    return i
{-# INLINE getLength #-}

putTag :: Tag -> Put
putTag (Tag t) = putWord8 t
{-# INLINE putTag #-}

dropTag :: Tag -> ErrorCode -> Get ()
dropTag x e = do
    t <- getTag
    when (t /= x) $ fail (show e)
{-# INLINE dropTag #-}

getTag :: Get Tag
getTag = Tag <$> getWord8
{-# INLINE getTag #-}

putIntegral :: Integral a => a -> Put
putIntegral = putOctets . bytesOfInt . fromIntegral
{-# INLINE putIntegral #-}

putIntegralU :: Integral a => a -> Put
putIntegralU = putOctets . bytesOfUInt . fromIntegral
{-# INLINE putIntegralU #-}

putBS :: ByteString -> Put
putBS bs = do
    putLength (B.length bs)
    putByteString bs
{-# INLINE putBS #-}

getBS :: Get ByteString
getBS = getLength >>= getByteString
{-# INLINE getBS #-}

putOctets :: [Word8] -> Put
putOctets bytes = do
    putLength (length bytes)
    mapM_ putWord8 bytes
{-# INLINE putOctets #-}

getOctets :: Get ByteString
getOctets = getLength >>= getBytes
{-# INLINE getOctets #-}

----------------------------------------------------------------------------------------------------

{- | uintOfBytes returns the number of bytes and the unsigned integer represented by the bytes -}
uintOfBytes :: ByteString -> (Int, Int)
uintOfBytes b = (B.length b, B.foldl' (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0 b)

--bytesOfUInt i = B.unfoldr (\x -> if x == 0 then Nothing else Just (fromIntegral (x .&. 0xff), x `shiftR` 8)) i
bytesOfUInt :: Int -> [Word8]
bytesOfUInt x = reverse (list x)
  where
    list i = if i <= 0xff
             then [fromIntegral i]
             else (fromIntegral i .&. 0xff) : list (i `shiftR` 8)

{- | intOfBytes returns the number of bytes in the list and
   the represented integer by a two's completement list of bytes -}
intOfBytes :: ByteString -> (Int, Int)
intOfBytes b
    | B.length b == 0 = (0, 0)
    | otherwise       = (len, if isNeg then -(maxIntLen - v + 1) else v)
  where
    (len, v)  = uintOfBytes b
    maxIntLen = 2 ^ (8 * len) - 1
    isNeg     = testBit (B.head b) 7

{- | bytesOfInt convert an integer into a two's completemented list of bytes -}
bytesOfInt :: Int -> [Word8]
bytesOfInt i
    | i > 0  = if testBit (head uints) 7 then 0 : uints else uints
    | i == 0 = [0]
    | otherwise  = if testBit (head nints) 7 then nints else 0xff : nints
  where
    uints = bytesOfUInt (abs i)
    nints = reverse . plusOne . reverse . map complement $ uints
    plusOne []     = [1]
    plusOne (x:xs) = if x == 0xff then 0 : plusOne xs else (x+1) : xs

putVarEncodingIntegral :: (Bits i, Integral i) => i -> Put
putVarEncodingIntegral = putBase128 False
  where
    setFlag True = setBit
    setFlag False = clearBit
    putBase128 flag n
        | n < 0x80    = putWord8 $ setFlag flag (fromIntegral n) 7
        | otherwise   = do
            putBase128 True $ shiftR n 7
            putWord8 $ setFlag flag (fromIntegral n) 7

getVarEncodingIntegral :: (Show i, Bits i, Integral i) => Get i
getVarEncodingIntegral = getWord8 >>= getBase128 0
  where
    getBase128 acc n
        | testBit n 7 =
            getWord8 >>= getBase128 (acc `shiftL` 7 + fromIntegral (clearBit n 7))
        | otherwise =
            return $ (acc `shiftL` 7) + fromIntegral n

----------------------------------------------------------------------------------------------------

getSize :: Get Size
getSize = toSize =<< fromIntegral <$> getWord8
  where
    toSize l
        | testBit l 7 = Size . uintbs <$> getBytes (clearBit l 7)
        | otherwise = return (Size l)
    {- uintbs return the unsigned int represented by the bytes -}
    uintbs = B.foldl' (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0

putSize :: Size -> Put
putSize (Size i)
    | i >= 0 && i <= 0x7f = putWord8 (fromIntegral i)
    | i < 0     = fail "8"
    | otherwise = mapM_ putWord8 (lenbytes : lw)
  where
    lw       = bytesOfUInt (fromIntegral i)
    lenbytes = fromIntegral (length lw .|. 0x80)

putOid :: Oid -> Put
putOid (Oid (i1:i2:ids)) =
    putNested putLength $ do
        putWord8 $ fromIntegral (i1 * 40 + i2)
        mapM_ putVarEncodingIntegral ids
putOid _ = fail "put oi"  -- TODO: Set error code

getOid :: Get Oid
getOid =
    getNested getLength $ do
        x <- getWord8
        ids <- isEmpty >>= go []
        let oi1 = fromIntegral (x `div` 40)
            oi2 = fromIntegral (x `mod` 40)
        return $ Oid (oi1:oi2:ids)
  where
    go acc True = return $ reverse acc
    go acc False = do
        i <- getVarEncodingIntegral
        isEmpty >>= go (i:acc)

putValue :: Value -> Put
putValue (Integer i)         = putTag (Tag 0x02) >> putIntegral i
putValue (BitString bs)      = putTag (Tag 0x03) >> putBS bs
putValue (OctetString bs)    = putTag (Tag 0x04) >> putBS bs
putValue Null              = putTag (Tag 0x05) >> putWord8 0
putValue (OI oi)            = putTag (Tag 0x06) >> putOid oi
putValue (IpAddress a b c d) = putTag (Tag 0x40) >> putOctets [a, b, c, d]
putValue (Counter32 i)       = putTag (Tag 0x41) >> putIntegralU i
putValue (Gauge32 i)         = putTag (Tag 0x42) >> putIntegralU i
putValue (TimeTicks i)       = putTag (Tag 0x43) >> putIntegralU i
putValue (Opaque bs)         = putTag (Tag 0x44) >> putBS bs
putValue (NsapAddress bs)    = putTag (Tag 0x45) >> putBS bs
putValue (Counter64 i)       = putTag (Tag 0x46) >> putIntegral i
putValue (UInteger32 i)      = putTag (Tag 0x47) >> putIntegralU i
putValue NoSuchObject      = putTag (Tag 0x80) >> putWord8 0
putValue NoSuchInstance    = putTag (Tag 0x81) >> putWord8 0
putValue EndOfMibView      = putTag (Tag 0x82) >> putWord8 0

getValue :: Get Value
getValue = do
    Tag t <- getTag
    case t of
        0x02 -> Integer . fromIntegral . snd . intOfBytes <$> getOctets
        0x03 -> BitString <$> getBS
        0x04 -> OctetString <$> getBS
        0x05 -> Null <$ getWord8
        0x06 -> OI <$> getOid
        0x40 -> do
            _ <- getSize
            IpAddress <$> getWord8 <*> getWord8 <*> getWord8 <*> getWord8
        0x41 -> Counter32 . fromIntegral . snd . uintOfBytes <$> getOctets
        0x42 -> Gauge32 . fromIntegral . snd . uintOfBytes <$> getOctets
        0x43 -> TimeTicks . fromIntegral . snd . uintOfBytes <$> getOctets
        0x44 -> Opaque <$> getBS
        0x45 -> NsapAddress <$> getBS
        0x46 -> Counter64 . fromIntegral . snd . uintOfBytes <$> getOctets
        0x47 -> UInteger32 . fromIntegral . snd . uintOfBytes <$> getOctets
        0x80 -> NoSuchObject <$ getWord8
        0x81 -> NoSuchInstance <$ getWord8
        0x82 -> EndOfMibView <$ getWord8
        _ -> fail "9"

instance Serialize Size where
    put = putSize
    {-# INLINE put #-}

    get = getSize
    {-# INLINE get #-}

instance Serialize Value where
    put = putValue
    {-# INLINE put #-}

    get = getValue
    {-# INLINE get #-}

----------------------------------------------------------------------------------------------------

getInteger :: Get Int32
getInteger = getValue >>= \case
    (Integer i) -> return i
    _ -> fail "7"
{-# INLINE getInteger #-}

getOctetString :: Get ByteString
getOctetString = getValue >>= \case
    (OctetString os) -> return os
    _ -> fail "7"
{-# INLINE getOctetString #-}

getOI :: Get Oid
getOI = getValue >>= \case
    (OI oi) -> return oi
    _ -> fail "7"
{-# INLINE getOI #-}

----------------------------------------------------------------------------------------------------

instance Serialize Version where
    put = putValue . Integer . mpModel
      where
        mpModel Version1 = 0
        mpModel Version2 = 1
        mpModel Version3 = 3
    {-# INLINE put #-}

    get = getInteger >>= toVersion
      where
        toVersion 0 = return Version1
        toVersion 1 = return Version2
        toVersion 3 = return Version3
        toVersion _ = fail "10"
    {-# INLINE get #-}

instance Serialize Community where
    put (Community bs) = putValue (OctetString bs)
    {-# INLINE put #-}

    get = Community <$> getOctetString
    {-# INLINE get #-}

instance Serialize (Header V2) where
    put (V2Header c) = put c
    {-# INLINE put #-}

    get = V2Header <$> get
    {-# INLINE get #-}

instance Serialize MessageID where
    put (MessageID x) = putValue (Integer x)
    {-# INLINE put #-}

    get = MessageID <$> getInteger
    {-# INLINE get #-}

instance Serialize MaxSize where
    put (MaxSize x) = putValue (Integer $ fromIntegral x)
    {-# INLINE put #-}

    get = MaxSize . fromIntegral <$> getInteger
    {-# INLINE get #-}

-- [ 0 - Reportable | 1 - Priv | 2 - Auth | _ | _ | _ | _ | _ ] - bits
instance Serialize Flag where
    put (Flag r pa) =
        let zero = zeroBits :: Word8
            reportable = if r then setBit zero 0 else zero
            privauth = case pa of
                           NoAuthNoPriv -> zero
                           AuthNoPriv -> setBit zero 2
                           AuthPriv -> setBit zero 1 .|. setBit zero 2
            flag = reportable .|. privauth
         in putValue $ OctetString (B.pack [flag])

    get = getOctetString >>= toFlag
      where
        toFlag f
            | B.length f /= 1 = fail "10"
            | otherwise =
                let [w] = B.unpack f
                    reportable = testBit w 0
                 in case (testBit w 1, testBit w 2) of
                        (True, True) -> return $ Flag reportable AuthPriv
                        (False, False) -> return $ Flag reportable NoAuthNoPriv
                        (False, True) -> return $ Flag reportable AuthNoPriv
                        _ -> fail "10" -- SnmpException 10

instance Serialize SecurityModel where
    put UserBasedSecurityModel = putValue (Integer 3)
    {-# INLINE put #-}

    get = getInteger >>= toSecurityModel
      where
        toSecurityModel 3 = return UserBasedSecurityModel
        toSecurityModel _ = fail "7" -- SnmpException 7
    {-# INLINE get #-}

instance Serialize EngineID where
    put (EngineID s) = putValue (OctetString s)
    {-# INLINE put #-}
    get = EngineID <$> getOctetString
    {-# INLINE get #-}

instance Serialize EngineBoot where
    put (EngineBoot x) = putValue (Integer x)
    {-# INLINE put #-}
    get = EngineBoot <$> getInteger
    {-# INLINE get #-}

instance Serialize EngineTime where
    put (EngineTime x) = putValue (Integer x)
    {-# INLINE put #-}
    get = EngineTime <$> getInteger
    {-# INLINE get #-}

instance Serialize Login where
    put (Login bs) = putValue (OctetString bs)
    {-# INLINE put #-}
    get = Login <$> getOctetString
    {-# INLINE get #-}

instance Serialize AuthenticationParameter where
    put (AuthenticationParameter bs) = putValue (OctetString bs)
    {-# INLINE put #-}
    get = AuthenticationParameter <$> getOctetString
    {-# INLINE get #-}

instance Serialize PrivacyParameter where
    put (PrivacyParameter bs) = putValue (OctetString bs)
    {-# INLINE put #-}
    get = PrivacyParameter <$> getOctetString
    {-# INLINE get #-}

instance Serialize SecurityParameter where
    put (SecurityParameter eid boots time username auth priv) = do
        putTag (Tag 0x04)
        putNested putLength $ do
            putTag (Tag 0x30)
            putNested putLength $ do
                put eid
                put boots
                put time
                put username
                put auth
                put priv
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x04) 9
        getNested getLength $ do
            dropTag (Tag 0x30) 9
            getNested getLength (SecurityParameter <$> get <*> get <*> get <*> get <*> get <*> get)
    {-# INLINE get #-}

instance Serialize (Header V3) where
    put (V3Header msgid maxSize flag securityModel securityParameter) = do
        putTag (Tag 0x30)
        putNested putLength $ do
            put msgid
            put maxSize
            put flag
            put securityModel
        put securityParameter
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x30) 9
        getNested getLength (V3Header <$> get <*> get <*> get <*> get) <*> get
    {-# INLINE get #-}

instance Serialize RequestID where
    put (RequestID rid') = putValue (Integer $ fromIntegral rid')
    {-# INLINE put #-}

    get = RequestID <$> getInteger
    {-# INLINE get #-}

instance Serialize ErrorStatus where
    put (ErrorStatus es') = putValue (Integer $ fromIntegral es')
    {-# INLINE put #-}

    get = ErrorStatus <$> getInteger
    {-# INLINE get #-}

instance Serialize ErrorIndex where
    put (ErrorIndex ei') = putValue (Integer $ fromIntegral ei')
    {-# INLINE put #-}

    get = ErrorIndex <$> getInteger
    {-# INLINE get #-}

instance Serialize Suite where
    put (Suite vbs) = putTag (Tag 0x30) >> putNested putLength (mapM_ put vbs)
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x30) 9
        Suite <$> getNested getLength (isEmpty >>= getSuite [])
      where
        getSuite xs True = return $ reverse xs
        getSuite xs False = do
            coupla <- get
            isEmpty >>= getSuite (coupla:xs)
    {-# INLINE get #-}

instance Serialize Coupla where
    put (Coupla oi val) = do
        putTag (Tag 0x30)
        putNested putLength (putValue (OI oi) >> putValue val)
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x30) 9
        getNested getLength (Coupla <$> getOI <*> getValue)
    {-# INLINE get #-}

instance Serialize (PDU V2) where
    put (PDU Request{..} suite) = do
        putTag $ toTag rt
        putNested putLength $ do
            put rid
            put es
            put ei
            put suite
      where
        toTag GetRequest = Tag 0xa0
        toTag GetNextRequest = Tag 0xa1
        toTag GetResponse = Tag 0xa2
        toTag SetRequest = Tag 0xa3
        toTag GetBulkRequest = Tag 0xa5
        toTag Inform = Tag 0xa6
        toTag V2Trap = Tag 0xa7
        toTag Report = Tag 0xa8
    {-# INLINE put #-}

    get = do
        rt <- fromTag =<< getTag
        getNested getLength (PDU <$> (Request rt <$> get <*> get <*> get) <*> get)
      where
        fromTag (Tag 0xa0) = return GetRequest
        fromTag (Tag 0xa1) = return GetNextRequest
        fromTag (Tag 0xa2) = return GetResponse
        fromTag (Tag 0xa3) = return SetRequest
        fromTag (Tag 0xa5) = return GetBulkRequest
        fromTag (Tag 0xa6) = return Inform
        fromTag (Tag 0xa7) = return V2Trap
        fromTag (Tag 0xa8) = return Report
        fromTag _ = fail "9"
    {-# INLINE get #-}

instance Serialize ContextEngineID where
    put (ContextEngineID bs) = putValue (OctetString bs)
    {-# INLINE put #-}

    get = ContextEngineID <$> getOctetString
    {-# INLINE get #-}

instance Serialize ContextName where
    put (ContextName bs) = putValue (OctetString bs)
    {-# INLINE put #-}

    get = ContextName <$> getOctetString
    {-# INLINE get #-}

instance Serialize (PDU V3) where
    put (ScopedPDU contextEngine contextName pdu) = do
        putTag (Tag 0x30)
        putNested putLength (put contextEngine >> put contextName >> put pdu)
    put (CryptedPDU bs) = putValue (OctetString bs)
    {-# INLINE put #-}

    get = do
        Tag t <- getTag
        case t of
            0x30 -> getNested getLength (ScopedPDU <$> get <*> get <*> get)
            0x04 -> CryptedPDU <$> getBS
            _ -> fail "9"
    {-# INLINE get #-}

instance Serialize Packet where
    put (V2Packet version header body) = do
        putTag (Tag 0x30)
        putNested putLength (put version >> put header >> put body)
    put (V3Packet version header body) = do
        putTag (Tag 0x30)
        putNested putLength (put version >> put header >> put body)
    {-# INLINE put #-}

    get = do
        dropTag (Tag 0x30) 9
        getNested getLength getAll
      where
        getAll = get >>= getPacket
        getPacket Version1 = V2Packet Version1 <$> get <*> get
        getPacket Version2 = V2Packet Version2 <$> get <*> get
        getPacket Version3 = V3Packet Version3 <$> get <*> get
    {-# INLINE get #-}

