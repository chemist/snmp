{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs             #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.Protocol.Snmp.Construct
    (
    -- * some classes and helpers
    -- *** universal, for work with both versions
      HasItem(..)
    -- *** v2 only, for work with Header V2
    , getCommunity
    , setCommunity
    -- *** v3 only, for work with Header V3, PDU V3
    , getID
    , getMaxSize
    , getFlag
    , getSecurityModel
    , getSecurityParameter
    , getAuthoritiveEngineId
    , getAuthoritiveEngineBoots
    , getAuthoritiveEngineTime
    , getUserName
    , getAuthenticationParameters
    , getPrivacyParameters
    , getContextEngineID
    , getContextName
    , setID
    , setMaxSize
    , setFlag
    , setSecurityModel
    , setSecurityParameter
    , setAuthoritiveEngineId
    , setAuthoritiveEngineBoots
    , setAuthoritiveEngineTime
    , setUserName
    , setAuthenticationParameters
    , setPrivacyParameters
    , setContextEngineID
    , setContextName
    -- *** create new Packet
    , Construct(..)
    -- ** helpers for work with Packet
    -- *** universal
    , getVersion
    , getRequest
    , setRequest
    , getRid
    , setRid
    , getSuite
    , setSuite
    , getErrorStatus
    , setErrorStatus
    -- *** v2 only
    , setCommunityP
    -- *** v3 only
    , setIDP
    , setMaxSizeP
    , setUserNameP
    , getAuthenticationParametersP
    , setAuthenticationParametersP
    , setReportableP
    , setPrivAuthP
    , getEngineIdP
    , setEngineIdP
    , getEngineBootsP
    , setEngineBootsP
    , getEngineTimeP
    , setEngineTimeP
    , getPrivParametersP
    , setPrivParametersP
    ) where

import           Data.ByteString             (ByteString)
import           Data.Int                    (Int32)

import           Network.Protocol.Snmp.Types

-- | initial new object, like mempty for monoid
class Construct a where
    initial :: a

instance Construct (Version -> Packet) where
    initial Version3 = V3Packet Version3 initial initial
    initial Version2 = V2Packet Version2 initial initial
    initial Version1 = V2Packet Version1 initial initial
    {-# INLINE initial #-}

instance Construct (Header V3) where
    initial = V3Header (ID 0) (MaxSize 65007) (Flag False NoAuthNoPriv) UserBasedSecurityModel initial
    {-# INLINE initial #-}

instance Construct (Header V2) where
    initial = V2Header (Community "")
    {-# INLINE initial #-}

instance Construct (PDU V3) where
    initial = ScopedPDU (ContextEngineID "") (ContextName "") initial
    {-# INLINE initial #-}

instance Construct (PDU V2) where
    initial = PDU initial initial
    {-# INLINE initial #-}

instance Construct SecurityParameter where
    initial = SecurityParameter "" 0 0 "" "" ""
    {-# INLINE initial #-}

instance Construct Suite where
    initial = Suite []
    {-# INLINE initial #-}

instance Construct Request where
    initial = GetRequest (RequestId 0) (ErrorStatus 0) (ErrorIndex 0)
    {-# INLINE initial #-}

----------------------------------------------------------------------------------------
-- | some universal getters, setters
class HasItem a where
    getHeader :: Packet -> Header a
    setHeader :: Header a -> Packet -> Packet
    getPDU :: Packet -> PDU a
    setPDU :: PDU a -> Packet -> Packet

instance HasItem V2 where
    getHeader (V2Packet _ x _) = x
    getHeader _ = undefined
    {-# INLINE getHeader #-}

    setHeader h (V2Packet v _ x) = V2Packet v h x
    setHeader _ _ = undefined
    {-# INLINE setHeader #-}

    getPDU (V2Packet _ _ x) = x
    getPDU _ = undefined
    {-# INLINE getPDU #-}

    setPDU p (V2Packet v h _) = V2Packet v h p
    setPDU _ _ = undefined
    {-# INLINE setPDU #-}

instance HasItem V3 where
    getHeader (V3Packet _ x _) = x
    getHeader _ = undefined
    {-# INLINE getHeader #-}

    setHeader h (V3Packet v _ x) = V3Packet v h x
    setHeader _ _ = undefined
    {-# INLINE setHeader #-}

    getPDU (V3Packet _ _ x) = x
    getPDU _ = undefined
    {-# INLINE getPDU #-}

    setPDU p (V3Packet v h _) = V3Packet v h p
    setPDU _ _ = undefined
    {-# INLINE setPDU #-}

----------------------------------------------------------------------------------------------------

getCommunity :: Header V2 -> Community
getCommunity (V2Header c) = c

setCommunity :: Community -> Header V2 -> Header V2
setCommunity c (V2Header _) = V2Header c

getID :: Header V3 -> ID
getID (V3Header i _ _ _ _) = i

getMaxSize :: Header V3 -> MaxSize
getMaxSize (V3Header _ i _ _ _) = i

getFlag :: Header V3 -> Flag
getFlag (V3Header _ _ i _ _) = i

getSecurityModel :: Header V3 -> SecurityModel
getSecurityModel (V3Header _ _ _ i _) = i

getSecurityParameter :: Header V3 -> SecurityParameter
getSecurityParameter (V3Header _ _ _ _ i) = i

getAuthoritiveEngineId :: Header V3 -> ByteString
getAuthoritiveEngineId = authoritiveEngineId . getSecurityParameter

getAuthoritiveEngineBoots :: Header V3 -> Int32
getAuthoritiveEngineBoots = authoritiveEngineBoots . getSecurityParameter

getAuthoritiveEngineTime :: Header V3 -> Int32
getAuthoritiveEngineTime = authoritiveEngineTime . getSecurityParameter

getUserName :: Header V3 -> ByteString
getUserName = userName . getSecurityParameter

getAuthenticationParameters :: Header V3 -> ByteString
getAuthenticationParameters = authenticationParameters . getSecurityParameter

getPrivacyParameters :: Header V3 -> ByteString
getPrivacyParameters = privacyParameters . getSecurityParameter

getContextEngineID :: PDU V3 -> ContextEngineID
getContextEngineID (ScopedPDU i _ _) = i
getContextEngineID _ = undefined

getContextName :: PDU V3 -> ContextName
getContextName (ScopedPDU _ i _) = i
getContextName _ = undefined

setID :: ID -> Header V3 -> Header V3
setID i (V3Header _ a b c d) = V3Header i a b c d

setMaxSize :: MaxSize -> Header V3 -> Header V3
setMaxSize i (V3Header a _ b c d) = V3Header a i b c d

setFlag :: Flag -> Header V3 -> Header V3
setFlag i (V3Header a b _ c d) = V3Header a b i c d

setSecurityModel :: SecurityModel -> Header V3 -> Header V3
setSecurityModel i (V3Header a b c _ d) = V3Header a b c i d

setSecurityParameter :: SecurityParameter -> Header V3 -> Header V3
setSecurityParameter i (V3Header a b c d _) = V3Header a b c d i

setAuthoritiveEngineId :: ByteString -> Header V3 -> Header V3
setAuthoritiveEngineId i (V3Header a b c d f) =
    V3Header a b c d (f { authoritiveEngineId = i })

setAuthoritiveEngineBoots :: Int32 -> Header V3 -> Header V3
setAuthoritiveEngineBoots i (V3Header a b c d f) =
    V3Header a b c d (f { authoritiveEngineBoots = i })

setAuthoritiveEngineTime :: Int32 -> Header V3 -> Header V3
setAuthoritiveEngineTime i (V3Header a b c d f) =
    V3Header a b c d (f { authoritiveEngineTime = i })

setUserName :: ByteString -> Header V3 -> Header V3
setUserName i (V3Header a b c d f) = V3Header a b c d (f { userName = i })

setAuthenticationParameters :: ByteString -> Header V3 -> Header V3
setAuthenticationParameters i (V3Header a b c d f) =
    V3Header a b c d (f { authenticationParameters = i })

setPrivacyParameters :: ByteString -> Header V3 -> Header V3
setPrivacyParameters i (V3Header a b c d f) =
    V3Header a b c d (f { privacyParameters = i })

setContextEngineID :: ContextEngineID -> PDU V3 -> PDU V3
setContextEngineID i (ScopedPDU _ b c) = ScopedPDU i b c
setContextEngineID _ _ = undefined

setContextName :: ContextName -> PDU V3 -> PDU V3
setContextName i (ScopedPDU a _ b) = ScopedPDU a i b
setContextName _ _ = undefined

----------------------------------------------------------------------------------------
setIDP :: ID -> Packet -> Packet
setIDP x p =
    let header = getHeader p :: Header V3
        newHeader = setID x header
    in setHeader newHeader p

setMaxSizeP :: MaxSize -> Packet -> Packet
setMaxSizeP x p =
    let header = getHeader p :: Header V3
        newHeader = setMaxSize x header
    in setHeader newHeader p

setCommunityP :: Community -> Packet -> Packet
setCommunityP x p =
    let header = getHeader p :: Header V2
        newHeader = setCommunity x header
    in setHeader newHeader p

getEngineIdP :: Packet -> EngineId
getEngineIdP p =
    let header = getHeader p :: Header V3
    in getAuthoritiveEngineId header

setEngineIdP :: EngineId -> Packet -> Packet
setEngineIdP x p =
  let header = getHeader p :: Header V3
      newHeader = setAuthoritiveEngineId x header
  in setHeader newHeader p

getEngineBootsP :: Packet -> EngineBootId
getEngineBootsP p =
    let header = getHeader p :: Header V3
    in getAuthoritiveEngineBoots header

setEngineBootsP :: EngineBootId -> Packet -> Packet
setEngineBootsP x p =
    let header = getHeader p :: Header V3
        newHeader = setAuthoritiveEngineBoots x header
    in setHeader newHeader p

getEngineTimeP :: Packet -> Int32
getEngineTimeP p =
    let header = getHeader p :: Header V3
    in getAuthoritiveEngineTime header

setEngineTimeP :: Int32 -> Packet -> Packet
setEngineTimeP x p =
    let header = getHeader p :: Header V3
        newHeader = setAuthoritiveEngineTime x header
    in setHeader newHeader p

setReportableP :: Reportable -> Packet -> Packet
setReportableP r p =
    let header = getHeader p :: Header V3
        Flag _ a = getFlag header
        newHeader = setFlag (Flag r a) header
    in setHeader newHeader p

setPrivAuthP :: PrivAuth -> Packet -> Packet
setPrivAuthP x p =
    let header = getHeader p :: Header V3
        Flag r _ = getFlag header
        newHeader = setFlag (Flag r x) header
    in setHeader newHeader p

setUserNameP :: ByteString -> Packet -> Packet
setUserNameP x p =
    let header = getHeader p :: Header V3
        sp = getSecurityParameter header
        newHeader = setSecurityParameter (sp { userName = x }) header
    in setHeader newHeader p

setAuthenticationParametersP :: ByteString -> Packet -> Packet
setAuthenticationParametersP x p =
    let header = getHeader p :: Header V3
        sp = getSecurityParameter header
        newHeader = setSecurityParameter (sp { authenticationParameters = x }) header
    in setHeader newHeader p

getAuthenticationParametersP :: Packet -> ByteString
getAuthenticationParametersP p =
    let header = getHeader p :: Header V3
    in authenticationParameters (getSecurityParameter header)

setPrivParametersP :: ByteString -> Packet -> Packet
setPrivParametersP x p =
    let header = getHeader p :: Header V3
        sp = getSecurityParameter header
        newHeader = setSecurityParameter (sp { privacyParameters = x }) header
    in setHeader newHeader p

getPrivParametersP :: Packet -> ByteString
getPrivParametersP p =
    let header = getHeader p :: Header V3
    in privacyParameters $ getSecurityParameter header

getVersion :: Packet -> Version
getVersion (V2Packet v _ _) = v
getVersion (V3Packet v _ _) = v

getRid :: Packet -> RequestId
getRid (V2Packet _ _ (PDU r _)) = rid r
getRid (V3Packet _ _ (ScopedPDU _ _ (PDU r _))) = rid r
getRid _ = undefined

setRid :: RequestId -> Packet -> Packet
setRid r (V2Packet v h (PDU req s)) = V2Packet v h (PDU req { rid = r } s)
setRid r (V3Packet v h (ScopedPDU a b (PDU req s))) = V3Packet v h (ScopedPDU a b (PDU req { rid = r } s))
setRid _ _ = undefined

getErrorStatus :: Packet -> ErrorStatus
getErrorStatus (V2Packet _ _ (PDU r _)) = es r
getErrorStatus (V3Packet _ _ (ScopedPDU _ _ (PDU r _))) = es r
getErrorStatus _ = undefined

setErrorStatus :: ErrorStatus -> Packet -> Packet
setErrorStatus e (V2Packet v h (PDU req s)) = V2Packet v h (PDU req { es = e } s)
setErrorStatus e (V3Packet v h (ScopedPDU a b (PDU req s))) = V3Packet v h (ScopedPDU a b (PDU req { es = e } s))
setErrorStatus _ _ = undefined

getSuite :: Packet -> Suite
getSuite (V2Packet _ _ (PDU _ r)) = r
getSuite (V3Packet _ _ (ScopedPDU _ _ (PDU _ r))) = r
getSuite _ = undefined

setSuite :: Suite -> Packet -> Packet
setSuite s (V2Packet v h (PDU req _)) = V2Packet v h (PDU req s)
setSuite s (V3Packet v h (ScopedPDU a b (PDU req _))) = V3Packet v h (ScopedPDU a b (PDU req s))
setSuite _ _ = undefined

getRequest :: Packet -> Request
getRequest (V2Packet _ _ (PDU r _)) = r
getRequest (V3Packet _ _ (ScopedPDU _ _ (PDU r _))) = r
getRequest _ = undefined

setRequest :: Request -> Packet -> Packet
setRequest req (V2Packet v h (PDU _ s)) = V2Packet v h (PDU req s)
setRequest req (V3Packet v h (ScopedPDU a b (PDU _ s))) = V3Packet v h (ScopedPDU a b (PDU req s))
setRequest _ _ = undefined

