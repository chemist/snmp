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
import qualified Crypto.Error                    as Priv
import qualified Crypto.Hash                     as Hash
import qualified Crypto.MAC.HMAC                 as HMAC
import           Data.Bits
import qualified Data.ByteArray                  as BA
import           Data.ByteString                 (ByteString)
import qualified Data.ByteString                 as B
import qualified Data.ByteString.Lazy            as BL
import           Data.Int                        (Int32, Int64)
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

hash :: (BA.ByteArray a) => AuthType -> ByteString -> a
hash MD5 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.MD5)
hash SHA bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA1)

hashlazy :: (BA.ByteArray a) => AuthType -> BL.ByteString -> a
hashlazy MD5 bs = BA.convert (Hash.hashlazy bs :: Hash.Digest Hash.MD5)
hashlazy SHA bs = BA.convert (Hash.hashlazy bs :: Hash.Digest Hash.SHA1)

hmac :: (BA.ByteArrayAccess key, BA.ByteArray msg) => AuthType -> key -> msg -> ByteString
hmac MD5 key msg = BA.convert (HMAC.hmac key msg :: HMAC.HMAC Hash.MD5)
hmac SHA key msg = BA.convert (HMAC.hmac key msg :: HMAC.HMAC Hash.SHA1)

-- | (only V3) sign Packet
signPacket :: AuthType -> Key -> Packet -> Packet
signPacket at (Key key) packet =
    let packetAsBin = encode packet
        sign = B.take 12 $ hmac at key packetAsBin
    in setAuthenticationParametersP sign packet

-- | create auth key from password and context engine id
passwordToKey :: AuthType -> Password -> EngineId -> Key
passwordToKey at (Password pass) eid =
  let buf = (BL.take 1048576 . BL.fromChunks . repeat) pass
      authKey = hashlazy at buf
  in Key $ hash at (authKey <> eid <> authKey)

type Salt = ByteString
type Encrypted = ByteString
type Raw = ByteString
type Rand32 = Int32
type Rand64 = Int64

desEncrypt :: Key -> EngineBootId -> Rand32 -> Raw -> (Encrypted, Salt)
desEncrypt (Key privKey) engineBoot localInt dataToEncrypt =
    let desKey = B.take 8 privKey
        preIV = B.drop 8 $ B.take 16 privKey
        salt = toSalt engineBoot localInt
        ivR = B.pack $ zipWith xor (B.unpack preIV) (B.unpack salt)
        Just iv = Priv.makeIV ivR :: Maybe (Priv.IV Priv.DES)
        -- Right key = Priv.makeKey desKey
        Priv.CryptoPassed des = Priv.cipherInit desKey :: Priv.CryptoFailable Priv.DES
        tailLen = (8 - B.length dataToEncrypt `rem` 8) `rem` 8
        tailB = B.replicate tailLen 0x00
    in (Priv.cbcEncrypt des iv (dataToEncrypt <> tailB), salt)

aesEncrypt :: Key -> EngineBootId -> EngineTime -> Rand64 -> Raw -> (Encrypted, Salt)
aesEncrypt (Key privKey) engineBoot engineTime rcounter dataToEncrypt =
    let aesKey = B.take 16 privKey
        salt = wToBs rcounter
        Just iv = Priv.makeIV $ toSalt engineBoot engineTime <> salt :: Maybe (Priv.IV Priv.AES128)
        -- Right key = Priv.makeKey aesKey
        Priv.CryptoPassed aes = Priv.cipherInit aesKey :: Priv.CryptoFailable Priv.AES128
    in (Priv.cfbEncrypt aes iv dataToEncrypt, salt)

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
desDecrypt (Key privKey) privParameters dataToDecrypt =
    let desKey = B.take 8 privKey
        preIV = B.drop 8 $ B.take 16 privKey
        salt = privParameters
        ivR = zipWith xor (B.unpack preIV) (B.unpack salt)
        Just iv = (Priv.makeIV (B.pack ivR) :: Maybe (Priv.IV Priv.DES))
        -- Right key = Priv.makeKey desKey
        Priv.CryptoPassed des = Priv.cipherInit desKey :: Priv.CryptoFailable Priv.DES
    in stripBS $ Priv.cbcDecrypt des iv dataToDecrypt

aesDecrypt :: Key -> Salt -> EngineBootId -> EngineTime -> Encrypted -> Raw
aesDecrypt (Key privKey) salt engineBoot engineTime dataToDecrypt =
    let aesKey = B.take 16 privKey
        ivR = toSalt engineBoot engineTime <> salt
        Just iv = (Priv.makeIV ivR :: Maybe (Priv.IV Priv.AES128))
        -- Right key = Priv.makeKey aesKey
        Priv.CryptoPassed aes = Priv.cipherInit aesKey :: Priv.CryptoFailable Priv.AES128
    in stripBS $ Priv.cfbDecrypt aes iv dataToDecrypt

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
    uintbs = B.foldl (\acc n -> (acc `shiftL` 8) + fromIntegral n) 0

