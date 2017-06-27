/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "NSSHelper.h"
#include "nss.h"
#include "ssl.h"
#include "sslproto.h"
#include "cert.h"
#include "certdb.h"
#include "pk11pub.h"
#include "secmod.h"
#include "assert.h"


#if NSS_VMAJOR < 3 || (NSS_VMINOR < 32 && NSS_VMAJOR == 3)
fail complie;
#endif

// the above version is not sufficient - the -20 xbranch hasn't been
// give a new vminor
/*
    nss -20 branch
    https://github.com/nss-dev/nss/tree/NSS_TLS13_DRAFT19_BRANCH
    
    known cset d48b10106e9e77a7ec9a8fffe64a681d775a0563
*/

// todo runtime enforce too

extern "C" 
{
// All of this hkdf code is copied from NSS

static const struct {
  SSLHashType hash;
  CK_MECHANISM_TYPE pkcs11Mech;
  unsigned int hashSize;
} kTlsHkdfInfo[] = {
  { ssl_hash_none, 0, 0 },
  { ssl_hash_md5, 0, 0 },
  { ssl_hash_sha1, 0, 0 },
  { ssl_hash_sha224, 0 },
  { ssl_hash_sha256, CKM_NSS_HKDF_SHA256, 32 },
  { ssl_hash_sha384, CKM_NSS_HKDF_SHA384, 48 },
  { ssl_hash_sha512, CKM_NSS_HKDF_SHA512, 64 }
};

/* Helper function to encode an unsigned integer into a buffer. */
static PRUint8 *
ssl_EncodeUintX(PRUint64 value, unsigned int bytes, PRUint8 *to)
{
  PRUint64 encoded;

  PORT_Assert(bytes > 0 && bytes <= sizeof(encoded));

  encoded = mozquic::htonll(value);
  memcpy(to, ((unsigned char *)(&encoded)) + (sizeof(encoded) - bytes), bytes);
  return to + bytes;
}
  
static SECStatus
tls13_HkdfExpandLabel(PK11SymKey *prk, SSLHashType baseHash,
                      const PRUint8 *handshakeHash, unsigned int handshakeHashLen,
                      const char *label, unsigned int labelLen,
                      CK_MECHANISM_TYPE algorithm, unsigned int keySize,
                      PK11SymKey **keyp)
{
  CK_NSS_HKDFParams params;
  SECItem paramsi = { siBuffer, NULL, 0 };
  /* Size of info array needs to be big enough to hold the maximum Prefix,
   * Label, plus HandshakeHash. If it's ever to small, the code will abort.
   */
  PRUint8 info[256];
  PRUint8 *ptr = info;
  unsigned int infoLen;
  PK11SymKey *derived;
  const char *kLabelPrefix = "tls13 ";
  const unsigned int kLabelPrefixLen = strlen(kLabelPrefix);

  if (handshakeHash) {
    if (handshakeHashLen > 255) {
      PORT_Assert(0);
      return SECFailure;
    }
  } else {
    PORT_Assert(!handshakeHashLen);
  }

  /*
   *  [draft-ietf-tls-tls13-11] Section 7.1:
   *
   *  HKDF-Expand-Label(Secret, Label, HashValue, Length) =
   *       HKDF-Expand(Secret, HkdfLabel, Length)
   *
   *  Where HkdfLabel is specified as:
   *
   *  struct HkdfLabel {
   *    uint16 length;
   *    opaque label<9..255>;
   *    opaque hash_value<0..255>;
   *  };
   *
   *  Where:
   *  - HkdfLabel.length is Length
   *  - HkdfLabel.hash_value is HashValue.
   *  - HkdfLabel.label is "TLS 1.3, " + Label
   *
   */
  infoLen = 2 + 1 + kLabelPrefixLen + labelLen + 1 + handshakeHashLen;
  if (infoLen > sizeof(info)) {
    PORT_Assert(0);
    goto abort;
  }

  ptr = ssl_EncodeUintX(keySize, 2, ptr);
  ptr = ssl_EncodeUintX(labelLen + kLabelPrefixLen, 1, ptr);
  PORT_Memcpy(ptr, kLabelPrefix, kLabelPrefixLen);
  ptr += kLabelPrefixLen;
  PORT_Memcpy(ptr, label, labelLen);
  ptr += labelLen;
  ptr = ssl_EncodeUintX(handshakeHashLen, 1, ptr);
  if (handshakeHash) {
    PORT_Memcpy(ptr, handshakeHash, handshakeHashLen);
    ptr += handshakeHashLen;
  }
  PORT_Assert((ptr - info) == infoLen);

  params.bExtract = CK_FALSE;
  params.bExpand = CK_TRUE;
  params.pInfo = info;
  params.ulInfoLen = infoLen;
  paramsi.data = (unsigned char *)&params;
  paramsi.len = sizeof(params);

  derived = PK11_DeriveWithFlags(prk, kTlsHkdfInfo[baseHash].pkcs11Mech,
                                 &paramsi, algorithm,
                                 CKA_DERIVE, keySize,
                                 CKF_SIGN | CKF_VERIFY);
  if (!derived)
    return SECFailure;

  *keyp = derived;
  return SECSuccess;

abort:
    return SECFailure;
}
  
static SECStatus
tls13_HkdfExpandLabelRaw(PK11SymKey *prk, SSLHashType baseHash,
                         const PRUint8 *handshakeHash, unsigned int handshakeHashLen,
                         const char *label, unsigned int labelLen,
                         unsigned char *output, unsigned int outputLen)
{
  PK11SymKey *derived = NULL;
  SECItem *rawkey;
  SECStatus rv;

  rv = tls13_HkdfExpandLabel(prk, baseHash, handshakeHash, handshakeHashLen,
                             label, labelLen,
                             kTlsHkdfInfo[baseHash].pkcs11Mech, outputLen,
                             &derived);
  if (rv != SECSuccess || !derived) {
    goto abort;
  }

  rv = PK11_ExtractKeyValue(derived);
  if (rv != SECSuccess) {
    goto abort;
  }

  rawkey = PK11_GetKeyData(derived);
  if (!rawkey) {
    goto abort;
  }

  PORT_Assert(rawkey->len == outputLen);
  memcpy(output, rawkey->data, outputLen);
  PK11_FreeSymKey(derived);

  return SECSuccess;

abort:
  if (derived) {
    PK11_FreeSymKey(derived);
  }
  return SECFailure;
}
} // extern c - nss include

namespace mozquic {
        
static bool mozQuicInit = false;
static PRDescIdentity nssHelperIdentity;
static PRIOMethods nssHelperMethods;
  
int
NSSHelper::Init(char *dir)
{
  if (mozQuicInit) {
    return MOZQUIC_ERR_GENERAL;
  }
  mozQuicInit = true;
  nssHelperIdentity = PR_GetUniqueIdentity("nssHelper");
  nssHelperMethods = *PR_GetDefaultIOMethods();

  nssHelperMethods.getpeername = NSPRGetPeerName;
  nssHelperMethods.getsocketoption = NSPRGetSocketOption;
  nssHelperMethods.connect = nssHelperConnect;
  nssHelperMethods.write = nssHelperWrite;
  nssHelperMethods.send = nssHelperSend;
  nssHelperMethods.recv = nssHelperRecv;
  nssHelperMethods.read = nssHelperRead;

  return (NSS_Init(dir) == SECSuccess) ? MOZQUIC_OK : MOZQUIC_ERR_GENERAL;
}

void
NSSHelper::HandshakeCallback(PRFileDesc *fd, void *client_data)
{
  fprintf(stderr,"handshakecallback\n");
  unsigned int bufLen = 0;
  unsigned char buf[256];
  SSLNextProtoState state;
  bool didHandshakeFail = false;

  PRFileDesc *tmpFD = fd;
  while (tmpFD && (tmpFD->identity != nssHelperIdentity)) {
    tmpFD = tmpFD->lower;
  }
  assert(tmpFD);
  NSSHelper *self = reinterpret_cast<NSSHelper *>(tmpFD->secret);

  if (SSL_GetNextProto(fd, &state, buf, &bufLen, 256) != SECSuccess ||
      bufLen != strlen(mozquic_alpn) ||
      memcmp(mozquic_alpn, buf, bufLen)) {
    didHandshakeFail = true;
  } else {
    SSLChannelInfo info;
    unsigned int secretSize = 48;

    if (SSL_GetChannelInfo(fd, &info, sizeof(info)) != SECSuccess) {
      didHandshakeFail = true;
    } else {
      if (info.cipherSuite == TLS_AES_128_GCM_SHA256) {
        secretSize = 32;
      } else if (info.cipherSuite == TLS_AES_256_GCM_SHA384) {
        secretSize = 48;
      } else if (info.cipherSuite == TLS_CHACHA20_POLY1305_SHA256) {
        secretSize = 32;
      } else {
        assert(false);
        didHandshakeFail = true;
      }
    }

    const char *label = self->mIsClient ?
      "EXPORTER-QUIC client 1-RTT Secret" : "EXPORTER-QUIC server 1-RTT Secret";
    unsigned char initialSecret[48];
    if (SSL_ExportKeyingMaterial(fd, label, strlen (label),
                                 false, (const unsigned char *)"", 0, initialSecret, secretSize) != SECSuccess) {
      didHandshakeFail = true;
    }

    PK11SlotInfo *slot = PK11_GetInternalSlot(); // todo free?
    SECItem key_item = {siBuffer, initialSecret, secretSize};
    self->mSymmetricKey = PK11_ImportSymKey(slot, CKM_SSL3_MASTER_KEY_DERIVE, PK11_OriginUnwrap,
                                            CKA_DERIVE, &key_item, NULL);

    // all currently defined aead algorithms have key length of 16
    SSLHashType hashType = TLS_AES_256_GCM_SHA384 ? ssl_hash_sha384 : ssl_hash_sha256;
    if (tls13_HkdfExpandLabelRaw(self->mSymmetricKey, hashType,
                                 (const unsigned char *)"", 0, "key", 3,
                                 self->mPacketProtectionKey, sizeof(self->mPacketProtectionKey)) != SECSuccess) {
      didHandshakeFail = true;
    }
    // iv length is max(8, n_min) - n_min is aead specific, but is 12 for everything currently known
    if (tls13_HkdfExpandLabelRaw(self->mSymmetricKey, hashType,
                                 (const unsigned char *)"", 0, "iv", 3,
                                 self->mPacketProtectionIV, sizeof(self->mPacketProtectionIV)) != SECSuccess) {
      didHandshakeFail = true;
    }

  }
  
  self->mHandshakeComplete = true;
  if (didHandshakeFail) {
    self->mHandshakeFailed = true;
  }
}

SECStatus
NSSHelper::BadCertificate(void *client_data, PRFileDesc *fd)
{
  while (fd && (fd->identity != nssHelperIdentity)) {
    fd = fd->lower;
  }
  assert(fd);
  NSSHelper *self = reinterpret_cast<NSSHelper *>(fd->secret);
  fprintf(stderr,"badcertificate override=%d\n",
          self->mQuicSession->IgnorePKI());
  return self->mQuicSession->IgnorePKI() ? SECSuccess : SECFailure;
}

// server version
NSSHelper::NSSHelper(MozQuic *quicSession, const char *originKey)
  : mQuicSession(quicSession)
  , mNSSReady(false)
  , mHandshakeComplete(false)
  , mHandshakeFailed(false)
  , mIsClient(false)
  , mSymmetricKey(nullptr)
{
  PRNetAddr addr;
  memset(&addr,0,sizeof(addr));
  addr.raw.family = PR_AF_INET;

  mFD = PR_CreateIOLayerStub(nssHelperIdentity, &nssHelperMethods);
  mFD->secret = (struct PRFilePrivate *)this;
  mFD = SSL_ImportFD(nullptr, mFD);
  SSL_OptionSet(mFD, SSL_SECURITY, true);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_CLIENT, false);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_SERVER, true);
  SSL_OptionSet(mFD, SSL_ENABLE_RENEGOTIATION, SSL_RENEGOTIATE_NEVER);
  SSL_OptionSet(mFD, SSL_NO_CACHE, true);
  SSL_OptionSet(mFD, SSL_ENABLE_SESSION_TICKETS, true);
  SSL_OptionSet(mFD, SSL_REQUEST_CERTIFICATE, false);
  SSL_OptionSet(mFD, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);

  SSL_OptionSet(mFD, SSL_ENABLE_NPN, false);
  SSL_OptionSet(mFD, SSL_ENABLE_ALPN, true);

  SSLVersionRange range = {SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3};
  SSL_VersionRangeSet(mFD, &range);
  SSL_HandshakeCallback(mFD, HandshakeCallback, nullptr);

  mNSSReady = true;
  
  unsigned char buffer[256];
  assert(strlen(mozquic_alpn) < 256);
  buffer[0] = strlen(mozquic_alpn);
  memcpy(buffer + 1, mozquic_alpn, strlen(mozquic_alpn));
  if (SSL_SetNextProtoNego(mFD,
                           buffer, strlen(mozquic_alpn) + 1) != SECSuccess) {
    mNSSReady = false;
  }

  CERTCertificate *cert =
    CERT_FindCertByNickname(CERT_GetDefaultCertDB(), originKey);
  if (cert) {
    SECKEYPrivateKey *key = PK11_FindKeyByAnyCert(cert, nullptr);
    if (key) {
      SECStatus rv = SSL_ConfigServerCert(mFD, cert, key, nullptr, 0);
      if (mNSSReady && rv == SECSuccess) {
        mNSSReady = true;
      }
    }
  }
    
  PR_Connect(mFD, &addr, 0);
  // if you Read() from the helper, it pulls through the tls layer from the mozquic::stream0 buffer where
  // peer data lke the client hello is stored.. if you Write() to the helper something
  // like "", the tls layer adds the server hello on the way out into mozquic::stream0

}

// client version
NSSHelper::NSSHelper(MozQuic *quicSession, const char *originKey, bool unused)
  : mQuicSession(quicSession)
  , mNSSReady(false)
  , mHandshakeComplete(false)
  , mHandshakeFailed(false)
  , mIsClient(true)
  , mSymmetricKey(nullptr)
{
  // todo most of this can be put in an init routine shared between c/s

  mFD = PR_CreateIOLayerStub(nssHelperIdentity, &nssHelperMethods);
  mFD->secret = (struct PRFilePrivate *)this;
  mFD = SSL_ImportFD(nullptr, mFD);
  SSL_OptionSet(mFD, SSL_SECURITY, true);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_CLIENT, true);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_SERVER, false);
  SSL_OptionSet(mFD, SSL_ENABLE_RENEGOTIATION, SSL_RENEGOTIATE_NEVER);
  SSL_OptionSet(mFD, SSL_NO_CACHE, true); // todo why does this cause fails?
  SSL_OptionSet(mFD, SSL_ENABLE_SESSION_TICKETS, true);
  SSL_OptionSet(mFD, SSL_REQUEST_CERTIFICATE, false);
  SSL_OptionSet(mFD, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);

  SSL_OptionSet(mFD, SSL_ENABLE_NPN, false);
  SSL_OptionSet(mFD, SSL_ENABLE_ALPN, true);

  SSLVersionRange range = {SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3};
  SSL_VersionRangeSet(mFD, &range);
  SSL_HandshakeCallback(mFD, HandshakeCallback, nullptr);
  SSL_BadCertHook(mFD, BadCertificate, nullptr);

  char module_name[] = "library=libnssckbi.so name=\"Root Certs\"";
  SECMODModule *module = SECMOD_LoadUserModule(module_name, NULL, PR_FALSE);

  mNSSReady = true;
  
  unsigned char buffer[256];
  assert(strlen(mozquic_alpn) < 256);
  buffer[0] = strlen(mozquic_alpn);
  memcpy(buffer + 1, mozquic_alpn, strlen(mozquic_alpn));
  if (SSL_SetNextProtoNego(mFD,
                           buffer, strlen(mozquic_alpn) + 1) != SECSuccess) {
    mNSSReady = false;
  }

  SSL_SetURL(mFD, originKey);
    
  PRNetAddr addr;
  memset(&addr,0,sizeof(addr));
  addr.raw.family = PR_AF_INET;
  PR_Connect(mFD, &addr, 0);
}

int
NSSHelper::nssHelperWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  // data (e.g. server hello) has come from nss and needs to be written into MozQuic
  // to be written out to the network in stream 0
  NSSHelper *self = reinterpret_cast<NSSHelper *>(fd->secret);
  self->mQuicSession->NSSOutput(aBuf, aAmount);
  return aAmount;
}

int
NSSHelper::nssHelperSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                           int , PRIntervalTime)
{
  return nssHelperWrite(aFD, aBuf, aAmount);
}

int32_t
NSSHelper::nssHelperRead(PRFileDesc *fd, void *buf, int32_t amount)
{
  // nss is asking for input, i.e. a client hello from stream 0 after
  // stream reassembly
  NSSHelper *self = reinterpret_cast<NSSHelper *>(fd->secret);
  return self->mQuicSession->NSSInput(buf, amount);
}

int32_t
NSSHelper::nssHelperRecv(PRFileDesc *fd, void *buf, int32_t amount, int flags,
                           PRIntervalTime timeout)
{
  return nssHelperRead(fd, buf, amount);
}

PRStatus
NSSHelper::NSPRGetPeerName(PRFileDesc *aFD, PRNetAddr *addr)
{
  memset(addr,0,sizeof(*addr));
  addr->raw.family = PR_AF_INET;
  return PR_SUCCESS;
}

PRStatus
NSSHelper::NSPRGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt)
{
  if (aOpt->option == PR_SockOpt_Nonblocking) {
    aOpt->value.non_blocking = PR_TRUE;
    return PR_SUCCESS;
  }
  return PR_FAILURE;
}

PRStatus
NSSHelper::nssHelperConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  return PR_SUCCESS;
}

uint32_t
NSSHelper::DriveHandshake()
{
  if (mHandshakeFailed) {
    return MOZQUIC_ERR_CRYPTO;
  }
  if (mHandshakeComplete) {
    return MOZQUIC_OK;
  }
  assert(mNSSReady);// todo
  if (!mNSSReady) {
    return MOZQUIC_ERR_GENERAL;
  }
  char data[4096];

  SSL_ForceHandshake(mFD);
  int32_t rd = PR_Read(mFD, data, 4096);
  if (mHandshakeComplete || (rd > 0)) {
    return MOZQUIC_OK;
  }
  if (rd == 0) {
    fprintf(stderr,"eof on pipe?\n");
    return MOZQUIC_ERR_IO;
  }
  if (PR_GetError() == PR_WOULD_BLOCK_ERROR) {
    return MOZQUIC_OK;
  }

  return MOZQUIC_ERR_GENERAL;
}

}
