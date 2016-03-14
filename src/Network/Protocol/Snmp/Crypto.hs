{-# LANGUAGE BangPatterns  #-}
{-# LANGUAGE TupleSections #-}
module Network.Protocol.Snmp.Crypto
    (
      AuthType(..)
    , PrivType(..)
    , Key(..)
    , Password(..)
    -- * authentication
    , passwordToKey
    , signPacket
    , cleanPass
    -- * priv
    , Salt
    , Raw
    , Encrypted
    , Rand32
    , Rand64
    , desEncrypt
    , desDecrypt
    , aesEncrypt
    , aesDecrypt
    , toSalt
    ) where

import           Control.Exception               (throw)
import qualified Crypto.Cipher.AES               as Priv
import qualified Crypto.Cipher.DES               as Priv
import qualified Crypto.Cipher.Types             as Priv
import qualified Crypto.Data.Padding             as Pad
import qualified Crypto.Error                    as Priv
import qualified Crypto.Hash                     as Hash
import qualified Crypto.MAC.HMAC                 as HMAC
import           Data.Bits
import qualified Data.ByteArray                  as BA
import           Data.ByteString                 (ByteString)
import qualified Data.ByteString                 as B
import qualified Data.ByteString.Lazy            as BL
import           Data.Int                        (Int32, Int64)
import           Data.Maybe
import           Data.Monoid                     ((<>))

import           Network.Protocol.Snmp.Construct
import           Network.Protocol.Snmp.Exception
import           Network.Protocol.Snmp.Serialize
import           Network.Protocol.Snmp.Types


data PrivType = DES | AES
  deriving (Show, Ord, Eq)

data AuthType = MD5 | SHA
  deriving (Show, Ord, Eq)

newtype Key = Key ByteString
  deriving (Show, Ord, Eq)

newtype Password = Password ByteString
  deriving (Show, Ord, Eq)

cleanPass :: ByteString
cleanPass = B.pack $ replicate 12 0x00
{-# INLINE cleanPass #-}

hash :: AuthType -> ByteString -> ByteString
hash MD5 = BA.convert . (Hash.hash :: ByteString -> Hash.Digest Hash.MD5)
hash SHA = BA.convert . (Hash.hash :: ByteString -> Hash.Digest Hash.SHA1)
{-# INLINE hash #-}

hashlazy :: AuthType -> BL.ByteString -> ByteString
hashlazy MD5 = BA.convert . (Hash.hashlazy :: BL.ByteString -> Hash.Digest Hash.MD5)
hashlazy SHA = BA.convert . (Hash.hashlazy :: BL.ByteString -> Hash.Digest Hash.SHA1)
{-# INLINE hashlazy #-}

hmac :: AuthType -> ByteString -> ByteString -> ByteString
hmac MD5 key = BA.convert . (HMAC.hmac key :: ByteString -> HMAC.HMAC Hash.MD5)
hmac SHA key = BA.convert . (HMAC.hmac key :: ByteString -> HMAC.HMAC Hash.SHA1)
{-# INLINE hmac #-}

-- | (only V3) sign Packet
signPacket :: AuthType -> Key -> Packet -> Packet
signPacket at (Key key) packet =
    setAuthenticationParametersP (mkAuthParam packet) packet
  where
    mkAuthParam = AuthenticationParameter . B.take 12 . hmac at key . encode
{-# INLINE signPacket #-}

-- | create auth key from password and context engine id
passwordToKey :: AuthType -> Password -> EngineID -> Key
passwordToKey at (Password pass) (EngineID eid) = Key $! hash at (authKey <> eid <> authKey)
  where
    mkAuthKey = hashlazy at . BL.take 1048576 . BL.fromChunks . repeat
    authKey = mkAuthKey pass
{-# INLINE passwordToKey #-}

type Salt = ByteString
type Encrypted = ByteString
type Raw = ByteString
type Rand32 = Int32
type Rand64 = Int64

mkCipher :: (Priv.Cipher c) => ByteString -> c
mkCipher = (\(Priv.CryptoPassed x) -> x) . Priv.cipherInit
{-# INLINE mkCipher #-}

desEncrypt :: Key -> EngineBoot -> Rand32 -> Raw -> (Encrypted, Salt)
desEncrypt (Key privKey) (EngineBoot eb) localInt =
    (, salt) . Priv.cbcEncrypt cipher iv . Pad.pad Pad.PKCS5
  where
    preIV = B.drop 8 (B.take 16 privKey)
    salt = toSalt eb localInt
    iv :: Priv.IV Priv.DES
    !iv = fromJust $ Priv.makeIV (B.pack $ B.zipWith xor preIV salt)
    !cipher = mkCipher (B.take 8 privKey)

aesEncrypt :: Key -> EngineBoot -> EngineTime -> Rand64 -> Raw -> (Encrypted, Salt)
aesEncrypt (Key privKey) (EngineBoot eb) (EngineTime et) rcounter =
    (, salt) . Priv.cfbEncrypt cipher iv
  where
    salt = wToBs rcounter
    iv :: Priv.IV Priv.AES128
    !iv = fromJust $ Priv.makeIV (toSalt eb et <> salt)
    !cipher = mkCipher (B.take 16 privKey)

wToBs :: Int64 -> ByteString
wToBs x = B.pack
    [ fromIntegral (x `shiftR` 56 .&. 0xff)
    , fromIntegral (x `shiftR` 48 .&. 0xff)
    , fromIntegral (x `shiftR` 40 .&. 0xff)
    , fromIntegral (x `shiftR` 32 .&. 0xff)
    , fromIntegral (x `shiftR` 24 .&. 0xff)
    , fromIntegral (x `shiftR` 16 .&. 0xff)
    , fromIntegral (x `shiftR` 8 .&. 0xff)
    , fromIntegral (x `shiftR` 0 .&. 0xff)
    ]

toSalt :: Int32 -> Int32 -> ByteString
toSalt x y = B.pack
    [ fromIntegral (x `shiftR` 24 .&. 0xff)
    , fromIntegral (x `shiftR` 16 .&. 0xff)
    , fromIntegral (x `shiftR`  8 .&. 0xff)
    , fromIntegral (x `shiftR`  0 .&. 0xff)
    , fromIntegral (y `shiftR` 24 .&. 0xff)
    , fromIntegral (y `shiftR` 16 .&. 0xff)
    , fromIntegral (y `shiftR`  8 .&. 0xff)
    , fromIntegral (y `shiftR`  0 .&. 0xff)
    ]

desDecrypt :: Key -> Salt -> Encrypted -> Raw
desDecrypt (Key privKey) salt =
    stripBS . Priv.cbcDecrypt cipher iv
  where
    preIV = B.drop 8 (B.take 16 privKey)
    iv :: Priv.IV Priv.DES
    !iv = fromJust $ Priv.makeIV (B.pack $ B.zipWith xor preIV salt)
    !cipher = mkCipher (B.take 8 privKey)

aesDecrypt :: Key -> Salt -> EngineBoot -> EngineTime -> Encrypted -> Raw
aesDecrypt (Key privKey) salt (EngineBoot eb) (EngineTime et) =
    stripBS . Priv.cfbDecrypt cipher iv
  where
    iv :: Priv.IV Priv.AES128
    !iv = fromJust $ Priv.makeIV (toSalt eb et <> salt)
    !cipher = mkCipher (B.take 16 privKey)

stripBS :: ByteString -> ByteString
stripBS bs =
    let bs' = B.drop 1 bs
        l1 = fromIntegral (B.head bs')
    in if testBit l1 7
        then case clearBit l1 7 of
                  0   -> throw $ SnmpException (ErrorStatus 12)
                  len ->
                    let size = uintbs (B.take len (B.drop 1 bs'))
                    in B.take (size + len + 2) bs
        else B.take (l1 + 2) bs
  where
    {- uintbs return the unsigned int represented by the bytes -}
    uintbs = B.foldl' (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0

