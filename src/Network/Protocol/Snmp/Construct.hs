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
    , getAuthoritativeEngineID
    , getAuthoritativeEngineBoots
    , getAuthoritativeEngineTime
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
    , setAuthoritativeEngineID
    , setAuthoritativeEngineBoots
    , setAuthoritativeEngineTime
    , setUserName
    , setAuthenticationParameters
    , setPrivacyParameters
    , setContextEngineID
    , setContextName
    -- *** create new Packet
    , Construct(..)
    -- ** helpers for work with Packet
    -- *** universal
    , getVersionP
    , getRequestP
    , setRequestP
    , getRidP
    , setRidP
    , getSuiteP
    , setSuiteP
    , getErrorStatusP
    , setErrorStatusP
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
    , getEngineIDP
    , setEngineIDP
    , getEngineBootsP
    , setEngineBootsP
    , getEngineTimeP
    , setEngineTimeP
    , getPrivParametersP
    , setPrivParametersP
    ) where

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
    initial = V3Header (MessageID 0) (MaxSize 65007) (Flag False NoAuthNoPriv) UserBasedSecurityModel initial
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
    initial = SecurityParameter (EngineID "") 0 0 (Login "") (AuthenticationParameter "") (PrivacyParameter "")
    {-# INLINE initial #-}

instance Construct Suite where
    initial = Suite []
    {-# INLINE initial #-}

instance Construct Request where
    initial = Request GetRequest (RequestID 0) (ErrorStatus 0) (ErrorIndex 0)
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

getID :: Header V3 -> MessageID
getID (V3Header i _ _ _ _) = i

getMaxSize :: Header V3 -> MaxSize
getMaxSize (V3Header _ i _ _ _) = i

getFlag :: Header V3 -> Flag
getFlag (V3Header _ _ i _ _) = i

getSecurityModel :: Header V3 -> SecurityModel
getSecurityModel (V3Header _ _ _ i _) = i

getSecurityParameter :: Header V3 -> SecurityParameter
getSecurityParameter (V3Header _ _ _ _ i) = i

getAuthoritativeEngineID :: Header V3 -> EngineID
getAuthoritativeEngineID = authoritativeEngineID . getSecurityParameter

getAuthoritativeEngineBoots :: Header V3 -> EngineBoot
getAuthoritativeEngineBoots = authoritativeEngineBoots . getSecurityParameter

getAuthoritativeEngineTime :: Header V3 -> EngineTime
getAuthoritativeEngineTime = authoritativeEngineTime . getSecurityParameter

getUserName :: Header V3 -> Login
getUserName = userName . getSecurityParameter

getAuthenticationParameters :: Header V3 -> AuthenticationParameter
getAuthenticationParameters = authenticationParameters . getSecurityParameter

getPrivacyParameters :: Header V3 -> PrivacyParameter
getPrivacyParameters = privacyParameters . getSecurityParameter

getSuite :: PDU a -> Suite
getSuite (PDU _ s) = s
getSuite (ScopedPDU _ _ (PDU _ s)) = s
getSuite _ = undefined

getRid :: PDU a -> RequestID
getRid (PDU (Request _ rid _ _) _) = rid
getRid (ScopedPDU _ _ pdu) = getRid pdu
getRid _ = undefined

getRequest :: PDU a -> Request
getRequest (PDU r _) = r
getRequest (ScopedPDU _ _ (PDU r _)) = r
getRequest _ = undefined

getErrorStatus :: PDU a -> ErrorStatus
getErrorStatus = getES . getRequest
  where
    getES (Request _ _ es _) = es

getContextEngineID :: PDU V3 -> ContextEngineID
getContextEngineID (ScopedPDU i _ _) = i
getContextEngineID _ = undefined

getContextName :: PDU V3 -> ContextName
getContextName (ScopedPDU _ i _) = i
getContextName _ = undefined

setID :: MessageID -> Header V3 -> Header V3
setID i (V3Header _ a b c d) = V3Header i a b c d

setMaxSize :: MaxSize -> Header V3 -> Header V3
setMaxSize i (V3Header a _ b c d) = V3Header a i b c d

setFlag :: Flag -> Header V3 -> Header V3
setFlag i (V3Header a b _ c d) = V3Header a b i c d

setSecurityModel :: SecurityModel -> Header V3 -> Header V3
setSecurityModel i (V3Header a b c _ d) = V3Header a b c i d

setSecurityParameter :: SecurityParameter -> Header V3 -> Header V3
setSecurityParameter i (V3Header a b c d _) = V3Header a b c d i

setAuthoritativeEngineID :: EngineID -> Header V3 -> Header V3
setAuthoritativeEngineID i (V3Header a b c d f) =
    V3Header a b c d (f { authoritativeEngineID = i })

setAuthoritativeEngineBoots :: EngineBoot -> Header V3 -> Header V3
setAuthoritativeEngineBoots i (V3Header a b c d f) =
    V3Header a b c d (f { authoritativeEngineBoots = i })

setAuthoritativeEngineTime :: EngineTime -> Header V3 -> Header V3
setAuthoritativeEngineTime i (V3Header a b c d f) =
    V3Header a b c d (f { authoritativeEngineTime = i })

setUserName :: Login -> Header V3 -> Header V3
setUserName i (V3Header a b c d f) = V3Header a b c d (f { userName = i })

setAuthenticationParameters :: AuthenticationParameter -> Header V3 -> Header V3
setAuthenticationParameters i (V3Header a b c d f) =
    V3Header a b c d (f { authenticationParameters = i })

setPrivacyParameters :: PrivacyParameter -> Header V3 -> Header V3
setPrivacyParameters i (V3Header a b c d f) =
    V3Header a b c d (f { privacyParameters = i })

setSuite :: Suite -> PDU a -> PDU a
setSuite s (PDU r _) = PDU r s
setSuite s (ScopedPDU a b (PDU r _)) = ScopedPDU a b (PDU r s)
setSuite _ _ = undefined

setRid :: RequestID -> PDU a -> PDU a
setRid rid (PDU (Request rt _ es ei) s) = PDU (Request rt rid es ei) s
setRid rid (ScopedPDU a b (PDU (Request rt _ es ei) s)) = ScopedPDU a b (PDU (Request rt rid es ei) s)
setRid _ _ = undefined

setRequest :: Request -> PDU a -> PDU a
setRequest r (PDU _ s) = PDU r s
setRequest r (ScopedPDU a b (PDU _ s)) = ScopedPDU a b (PDU r s)
setRequest _ _ = undefined

setErrorStatus :: ErrorStatus -> PDU a -> PDU a
setErrorStatus es (PDU (Request rt rid _ ei) s) = PDU (Request rt rid es ei) s
setErrorStatus es (ScopedPDU a b (PDU (Request rt rid _ ei) s)) = ScopedPDU a b (PDU (Request rt rid es ei) s)
setErrorStatus _ _ = undefined

setContextEngineID :: ContextEngineID -> PDU V3 -> PDU V3
setContextEngineID i (ScopedPDU _ b c) = ScopedPDU i b c
setContextEngineID _ _ = undefined

setContextName :: ContextName -> PDU V3 -> PDU V3
setContextName i (ScopedPDU a _ b) = ScopedPDU a i b
setContextName _ _ = undefined

----------------------------------------------------------------------------------------
setIDP :: MessageID -> Packet -> Packet
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

getEngineIDP :: Packet -> EngineID
getEngineIDP = getAuthoritativeEngineID . getHeader

setEngineIDP :: EngineID -> Packet -> Packet
setEngineIDP x p =
  let header = getHeader p :: Header V3
      newHeader = setAuthoritativeEngineID x header
  in setHeader newHeader p

getEngineBootsP :: Packet -> EngineBoot
getEngineBootsP = getAuthoritativeEngineBoots . getHeader

setEngineBootsP :: EngineBoot -> Packet -> Packet
setEngineBootsP x p =
    let header = getHeader p :: Header V3
        newHeader = setAuthoritativeEngineBoots x header
    in setHeader newHeader p

getEngineTimeP :: Packet -> EngineTime
getEngineTimeP = getAuthoritativeEngineTime . getHeader

setEngineTimeP :: EngineTime -> Packet -> Packet
setEngineTimeP x p =
    let header = getHeader p :: Header V3
        newHeader = setAuthoritativeEngineTime x header
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

setUserNameP :: Login -> Packet -> Packet
setUserNameP x p =
    let header = getHeader p :: Header V3
        sp = getSecurityParameter header
        newHeader = setSecurityParameter (sp { userName = x }) header
    in setHeader newHeader p

setAuthenticationParametersP :: AuthenticationParameter -> Packet -> Packet
setAuthenticationParametersP x p =
    let header = getHeader p :: Header V3
        sp = getSecurityParameter header
        newHeader = setSecurityParameter (sp { authenticationParameters = x }) header
    in setHeader newHeader p

getAuthenticationParametersP :: Packet -> AuthenticationParameter
getAuthenticationParametersP = authenticationParameters . getSecurityParameter . getHeader

setPrivParametersP :: PrivacyParameter -> Packet -> Packet
setPrivParametersP x p =
    let header = getHeader p :: Header V3
        sp = getSecurityParameter header
        newHeader = setSecurityParameter (sp { privacyParameters = x }) header
    in setHeader newHeader p

getPrivParametersP :: Packet -> PrivacyParameter
getPrivParametersP = privacyParameters . getSecurityParameter . getHeader

getVersionP :: Packet -> Version
getVersionP (V2Packet v _ _) = v
getVersionP (V3Packet v _ _) = v

getRidP :: Packet -> RequestID
getRidP (V2Packet _ _ pdu) = getRid pdu
getRidP (V3Packet _ _ pdu) = getRid pdu

setRidP :: RequestID -> Packet -> Packet
setRidP r (V2Packet v h pdu) = V2Packet v h $ setRid r pdu
setRidP r (V3Packet v h pdu) = V3Packet v h $ setRid r pdu

getErrorStatusP :: Packet -> ErrorStatus
getErrorStatusP (V2Packet _ _ pdu) = getErrorStatus pdu
getErrorStatusP (V3Packet _ _ pdu) = getErrorStatus pdu

setErrorStatusP :: ErrorStatus -> Packet -> Packet
setErrorStatusP e (V2Packet v h pdu) = V2Packet v h $ setErrorStatus e pdu
setErrorStatusP e (V3Packet v h pdu) = V3Packet v h $ setErrorStatus e pdu

getSuiteP :: Packet -> Suite
getSuiteP (V2Packet _ _ pdu) = getSuite pdu
getSuiteP (V3Packet _ _ pdu) = getSuite pdu

setSuiteP :: Suite -> Packet -> Packet
setSuiteP s (V2Packet v h pdu) = V2Packet v h $ setSuite s pdu
setSuiteP s (V3Packet v h pdu) = V3Packet v h $ setSuite s pdu

getRequestP :: Packet -> Request
getRequestP (V2Packet _ _ pdu) = getRequest pdu
getRequestP (V3Packet _ _ pdu) = getRequest pdu

setRequestP :: Request -> Packet -> Packet
setRequestP req (V2Packet v h pdu) = V2Packet v h $ setRequest req pdu
setRequestP req (V3Packet v h pdu) = V3Packet v h $ setRequest req pdu

