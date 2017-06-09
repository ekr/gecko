/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "MozQuicStream.h"
#include "NSSHelper.h"

#include "assert.h"
#include "netinet/ip.h"
#include "stdlib.h"
#include "unistd.h"
#include "time.h"
#include "fnv.h"
#include "sys/time.h"
#include <string.h>
#include <fcntl.h>
#include "prerror.h"
#include "ufloat16.h"

#ifdef __cplusplus
extern "C" {
#endif
  static bool mozQuicInit = false;

  int mozquic_new_connection(mozquic_connection_t **outConnection,
                             mozquic_config_t *inConfig)
  {
    if (!outConnection || !inConfig) {
      return MOZQUIC_ERR_INVALID;
    }

    if (!inConfig->originName) {
      return MOZQUIC_ERR_INVALID;
    }

    mozquic::MozQuic *q = new mozquic::MozQuic(inConfig->handleIO);
    if (!q) {
      return MOZQUIC_ERR_GENERAL;
    }
    *outConnection = (void *)q;

    q->SetClosure(inConfig->closure);
    q->SetLogger(inConfig->logging_callback);
    q->SetTransmiter(inConfig->send_callback);
    q->SetReceiver(inConfig->recv_callback);
    q->SetHandshakeInput(inConfig->handshake_input);
    q->SetErrorCB(inConfig->error_callback);
    q->SetOriginPort(inConfig->originPort);
    q->SetOriginName(inConfig->originName);
    if (inConfig->greaseVersionNegotiation) {
      q->GreaseVersionNegotiation();
    }
    return MOZQUIC_OK;
  }

  int mozquic_destroy_connection(mozquic_connection_t *conn)
  {
    mozquic::MozQuic *self(reinterpret_cast<mozquic::MozQuic *>(conn));
    delete self;
    return MOZQUIC_OK;
  }

  int mozquic_start_connection(mozquic_connection_t *conn)
  {
    mozquic::MozQuic *self(reinterpret_cast<mozquic::MozQuic *>(conn));
    return self->StartConnection();
  }

  int mozquic_start_server(mozquic_connection_t *conn,
                           int (*handle_new_connection)(void *, mozquic_connection_t *newconn))
  {
    mozquic::MozQuic *self(reinterpret_cast<mozquic::MozQuic *>(conn));
    return self->StartServer(handle_new_connection);
  }
  
  int mozquic_IO(mozquic_connection_t *conn)
  {
    mozquic::MozQuic *self(reinterpret_cast<mozquic::MozQuic *>(conn));
    return self->IO();
  }

  mozquic_socket_t mozquic_osfd(mozquic_connection_t *conn)
  {
    mozquic::MozQuic *self(reinterpret_cast<mozquic::MozQuic *>(conn));
    return self->GetFD();
  }

  void mozquic_setosfd(mozquic_connection_t *conn, mozquic_socket_t fd)
  {
    mozquic::MozQuic *self(reinterpret_cast<mozquic::MozQuic *>(conn));
    self->SetFD(fd);
  }

  void mozquic_handshake_output(mozquic_connection_t *conn,
                                unsigned char *data, uint32_t data_len)
  {
    mozquic::MozQuic *self(reinterpret_cast<mozquic::MozQuic *>(conn));
    self->HandshakeOutput(data, data_len);
  }

  void mozquic_handshake_complete(mozquic_connection_t *conn, uint32_t errCode)
  {
    mozquic::MozQuic *self(reinterpret_cast<mozquic::MozQuic *>(conn));
    self->HandshakeComplete(errCode);
  }

  int mozquic_nss_config(char *dir) 
  {
    if (mozQuicInit) {
      return MOZQUIC_ERR_GENERAL;
    }
    mozQuicInit = true;
    if (!dir) {
      return MOZQUIC_ERR_INVALID;
    }

    return mozquic::NSSHelper::Init(dir);
  }
  
#ifdef __cplusplus
}
#endif

namespace mozquic  {

// when this set is updated, look at versionOK() and
// GenerateVersionNegotiation()
static const uint32_t kMozQuicVersion1 = 0xf123f0c5;
static const uint32_t kMozQuicIetfID3 = 0xff000003;
static const uint32_t kMozQuicVersionGreaseC = 0xfa1a7a3a;
static const uint32_t kMozQuicVersionGreaseS = 0xea0a6a2a;

MozQuic::MozQuic(bool handleIO)
  : mFD(MOZQUIC_SOCKET_BAD)
  , mHandleIO(handleIO)
  , mIsClient(true)
  , mIsChild(false)
  , mReceivedServerClearText(false)
  , mConnectionState(STATE_UNINITIALIZED)
  , mOriginPort(-1)
  , mVersion(kMozQuicVersion1)
  , mConnectionID(0)
  , mNextPacketNumber(0)
  , mOriginalPacketNumber(0)
  , mClosure(this)
  , mLogCallback(nullptr)
  , mTransmitCallback(nullptr)
  , mReceiverCallback(nullptr)
  , mHandshakeInput(nullptr)
  , mErrorCB(nullptr)
  , mNewConnCB(nullptr)
{
  assert(!handleIO); // todo
  unsigned char seed[4];
  if (SECSuccess != PK11_GenerateRandom(seed, sizeof(seed))) {
    // major badness!
    srandom(Timestamp() & 0xffffffff);
  } else {
    srandom(seed[0] << 24 | seed[1] << 16 | seed[2] << 8 | seed[3]);
  }
  memset(&mPeer, 0, sizeof(mPeer));
}

MozQuic::~MozQuic()
{
  if (!mIsChild && (mFD != MOZQUIC_SOCKET_BAD)) {
    close(mFD);
  }
}

void
MozQuic::GreaseVersionNegotiation()
{
  assert(mConnectionState == STATE_UNINITIALIZED);
  mVersion = kMozQuicVersionGreaseC;
}

int
MozQuic::StartConnection()
{
  assert(!mHandleIO); // todo
  mIsClient = true;
  mStream0.reset(new MozQuicStreamPair(0, this));

  mConnectionState = CLIENT_STATE_1RTT;
  for (int i=0; i < 4; i++) {
    mConnectionID = mConnectionID << 16;
    mConnectionID = mConnectionID | (random() & 0xffff);
  }
  for (int i=0; i < 2; i++) {
    mNextPacketNumber = mNextPacketNumber << 16;
    mNextPacketNumber = mNextPacketNumber | (random() & 0xffff);
  }
  mNextPacketNumber &= 0x7fffffff; // 31 bits
  mOriginalPacketNumber = mNextPacketNumber;

  return MOZQUIC_OK;
}

int
MozQuic::StartServer(int (*handle_new_connection)(void *, mozquic_connection_t *))
{
  assert(!mHandleIO); // todo
  mNewConnCB = handle_new_connection;
  mIsClient = false;

  mConnectionState = SERVER_STATE_LISTEN;
  assert (!mHandshakeInput); // todo
  return Bind();
}

void
MozQuic::SetOriginName(const char *name) 
{
  mOriginName.reset(new char[strlen(name) + 1]);
  strcpy (mOriginName.get(), name);
}

int
MozQuic::Bind()
{
  if (mFD != MOZQUIC_SOCKET_BAD) {
    return MOZQUIC_OK;
  }
  mFD = socket(AF_INET, SOCK_DGRAM, 0); // todo v6 and non 0 addr
  fcntl(mFD, F_SETFL, fcntl(mFD, F_GETFL, 0) | O_NONBLOCK);
  struct sockaddr_in sin;
  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(mOriginPort);
  bind(mFD, (const sockaddr *)&sin, sizeof (sin)); // todo err check
  listen(mFD, 1000); // todo err
  return MOZQUIC_OK;
}

MozQuic *
MozQuic::FindSession(const unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  assert (!mIsChild);
  assert (!mIsClient);
  assert (VersionOK(header.mVersion));
  // todo, this needs to work with short headers
  // probly means an abstract headerdata..

  auto i = mConnectionHash.find(header.mConnectionID);
  if (i == mConnectionHash.end()) {
    Log((char *)"find session could not find id in hash");
    return nullptr;
  }
  return (*i).second;
}

bool
MozQuic::IntegrityCheck(unsigned char *pkt, uint32_t pktSize) 
{
  assert (pkt[0] & 0x80);
  assert (((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_INITIAL) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_SERVER_STATELESS_RETRY) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_SERVER_CLEARTEXT) ||
          ((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_CLEARTEXT));
  if (pktSize < (FNV64size + 17)) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"hash err");
    return false;
  }
  unsigned char calculatedSum[FNV64size];
  if (FNV64block(pkt, pktSize - FNV64size, calculatedSum) != 0) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"hash err");
    return false;
  }
  bool rv = !memcmp(calculatedSum, pkt + pktSize - FNV64size, FNV64size);
  if (!rv) {
    Log((char *)"integrity error");
  }
  return rv;
}

uint32_t
MozQuic::Intake()
{
  if (mIsChild) {
    // parent does all fd reading
    return MOZQUIC_OK;
  }
  // check state
  assert (mConnectionState == SERVER_STATE_LISTEN ||
          mConnectionState == SERVER_STATE_1RTT ||
          mConnectionState == CLIENT_STATE_CONNECTED ||
          mConnectionState == CLIENT_STATE_1RTT); // todo mvp
  uint32_t rv = MOZQUIC_OK;
  
  unsigned char pkt[kMozQuicMSS];
  do {
    uint32_t pktSize = 0;
    struct sockaddr_in client;
    rv = Recv(pkt, kMozQuicMSS, pktSize, &client);
    // todo 17 assumes long form
    if (rv != MOZQUIC_OK || !pktSize || pktSize < 17) {
      return rv;
    }
    Log((char *)"intake found data");

    if (!(pkt[0] & 0x80)) {
      // short form header when we only expect long form
      // cleartext
      Log((char *)"short form header at wrong time");
      continue;
    }

    // dispatch to the right MozQuic class.
    MozQuic *session = this; // default

    LongHeaderData header(pkt, pktSize);
    fprintf(stderr,"PACKET RECVD %lX %X len=%d\n", header.mPacketNumber, header.mVersion, pktSize);
    if (!(VersionOK(header.mVersion) ||
          (mIsClient && header.mType == PACKET_TYPE_VERSION_NEGOTIATION && header.mVersion == mVersion))) {
      // todo this could really be an amplifier
      session->GenerateVersionNegotiation(header, &client);
      continue;
    }

    switch (header.mType) {
    case PACKET_TYPE_VERSION_NEGOTIATION:
      // do not do integrity check (nop)
      break;
    case PACKET_TYPE_CLIENT_INITIAL:
    case PACKET_TYPE_SERVER_CLEARTEXT:
      if (!IntegrityCheck(pkt, pktSize)) {
        rv = MOZQUIC_ERR_GENERAL;
      }
      break;
    case PACKET_TYPE_SERVER_STATELESS_RETRY:
      if (!IntegrityCheck(pkt, pktSize)) {
        rv = MOZQUIC_ERR_GENERAL;
      }
      assert(false); // todo mvp
      break;
    case PACKET_TYPE_CLIENT_CLEARTEXT:
      if (!IntegrityCheck(pkt, pktSize)) {
        rv = MOZQUIC_ERR_GENERAL;
        break;
      }
      session = FindSession(pkt, pktSize, header);
      if (!session) {
        rv = MOZQUIC_ERR_GENERAL;
      }
      break;

    default:
      // reject anything that is not a cleartext packet (not right, but later)
      Log((char *)"recv1rtt unexpected type");
      // todo this could actually be out of order protected packet even in handshake
      // and ideally would be queued. for now we rely on retrans
      // todo
      rv = MOZQUIC_ERR_GENERAL;
      break;
    }

    if (!session || rv != MOZQUIC_OK) {
      continue;
    }

    switch (header.mType) {
    case PACKET_TYPE_VERSION_NEGOTIATION: // version negotiation
      rv = session->ProcessVersionNegotiation(pkt, pktSize, header);
      // do not ack
      break;
    case PACKET_TYPE_CLIENT_INITIAL:
      rv = session->ProcessClientInitial(pkt, pktSize, &client, header, &session);
      // ack after processing - find new session
      if (rv == MOZQUIC_OK) {
        session->Acknowledge(pkt, pktSize, header);
      }
      break;
    case PACKET_TYPE_SERVER_STATELESS_RETRY:
      // do not ack
      // todo mvp
      break;
    case PACKET_TYPE_SERVER_CLEARTEXT:
      session->Acknowledge(pkt, pktSize, header);
      rv = session->ProcessServerCleartext(pkt, pktSize, header);
      break;
    case PACKET_TYPE_CLIENT_CLEARTEXT:
      session->Acknowledge(pkt, pktSize, header);
      rv = session->ProcessClientCleartext(pkt, pktSize, header);
      break;

    default:
      assert(false);
      break;
    }
  } while (rv == MOZQUIC_OK);

  return rv;
}

int
MozQuic::IO()
{
  uint32_t code;
  fprintf(stderr,"."); fflush(stderr);

  Intake();
  RetransmitTimer();
  Flush();

  if (mIsClient) {
    switch (mConnectionState) {
    case CLIENT_STATE_1RTT:
      code = Client1RTT();
      if (code != MOZQUIC_OK) {
        return code;
      }
      break;
    case CLIENT_STATE_CONNECTED:
      // todo mvp
      break;
    default:
      assert(false);
      // todo
    }
  } else {
    if (mConnectionState == SERVER_STATE_1RTT) {
      code = Server1RTT();
      if (code != MOZQUIC_OK) {
        return code;
      }
    }
  }
  
  return MOZQUIC_OK;
}

void
MozQuic::Log(char *msg) 
{
  // todo default mLogCallback can be dev/null
  if (mLogCallback) {
    mLogCallback(mClosure, msg);
  } else {
    fprintf(stderr,"MozQuic Logger :%s:\n", msg);
  }
}

void
MozQuic::AckScoreboard(uint64_t packetNumber)
{
  // scoreboard is ordered like this.. (with gap @4 @3)
  // 7/2, 2/1
  // todo out of order packets should be coalesced

  // todo if this list is too long, we can stop doing this according to
  // the spec

  if (mAckScoreboard.empty()) {
    mAckScoreboard.emplace_front(packetNumber, Timestamp());
    return;
  }

  auto iter=mAckScoreboard.begin();
  for (; iter != mAckScoreboard.end(); ++iter) {
    if ((iter->mPacketNumber + 1) == packetNumber) {
      // the common case is to just adjust this counter
      // in the first element
      iter->mPacketNumber++;
      iter->mExtra++;
      return;
    }
    if (iter->mPacketNumber >= packetNumber &&
        packetNumber >= (iter->mPacketNumber - iter->mExtra)) {
      return; // dup
    }
    if (iter->mPacketNumber < packetNumber) {
      break;
    }
  }
  mAckScoreboard.emplace(iter, packetNumber, Timestamp());
}

void
MozQuic::MaybeSendAck()
{
  if (mAckScoreboard.empty()) {
    return;
  }

  // if we aren't in connected we will only piggyback
  if (mConnectionState != CLIENT_STATE_CONNECTED &&
      mConnectionState != SERVER_STATE_CONNECTED) {
    return;
  }
  // todo for doing some kind of delack
  // todo generally
  assert(false);
}

uint32_t
MozQuic::AckPiggyBack(unsigned char *pkt, uint32_t avail,
                      enum mozquicKeyPhase keyPhase, uint32_t &used)
{
  used = 0;

  // build as many ack frames as will fit
  if (keyPhase == QuicKeyPhaseUnprotected) {
    // always use 32 bits and no timestamps and never
    // put more than 1 block in a frame. keep it simple.

    while (!mAckScoreboard.empty()) {
      if (avail < 10) {
        return MOZQUIC_OK;
      }
      pkt[0] = 0xa9; // ack with 32 bit num and 16 bit extra no ts
      pkt[1] = 0;

      auto iter = mAckScoreboard.rbegin();
      
      if (iter->mPacketNumber > 0xffffffff) {
        // > 32bit
        mAckScoreboard.pop_back();
        RaiseError(MOZQUIC_ERR_GENERAL, (char *)"unexpected packet number");
        return MOZQUIC_ERR_GENERAL;
      }

      uint32_t packet32 = iter->mPacketNumber;
      packet32 = htonl(packet32);
      memcpy(pkt + 2, &packet32, 4);
      // timestamp is microseconds (10^-6) as 16 bit fixed point #
      uint64_t delay64 = (Timestamp() - iter->mReceiveTime) * 1000;
      uint16_t delay = htons(ufloat16_encode(delay64));
      memcpy(pkt + 6, &delay, 2);
      uint16_t extra = htons(iter->mExtra);
      memcpy(pkt + 8, &extra, 2);
      pkt += 10;
      used += 10;
      avail -= 10;
      mAckScoreboard.pop_back();
    };
    return MOZQUIC_OK;
  }
  assert(false); // todo non handshake cases
  return MOZQUIC_OK;
}

void
MozQuic::Acknowledge(unsigned char *pkt, uint32_t pktLen, LongHeaderData &header)
{
  assert(mIsChild || mIsClient);
  // todo assumes long header
  if (pktLen < 17) {
    return;
  }
  if ((header.mType == PACKET_TYPE_VERSION_NEGOTIATION) ||
      (header.mType == PACKET_TYPE_SERVER_STATELESS_RETRY) ||
      (header.mType == PACKET_TYPE_PUBLIC_RESET)) {
    return;
  }
  fprintf(stderr,"%p GEN ACK FOR %lX\n", this, header.mPacketNumber);

  // put this packetnumber on the scoreboard along with timestamp
  AckScoreboard(header.mPacketNumber);
}

uint32_t
MozQuic::Recv(unsigned char *pkt, uint32_t avail, uint32_t &outLen,
              struct sockaddr_in *peer)
{
  uint32_t code = MOZQUIC_OK;

  if (mReceiverCallback) {
    code = mReceiverCallback(mClosure, pkt, avail, &outLen);
  } else {
    socklen_t sinlen = sizeof(*peer);
    ssize_t amt =
      recvfrom(mFD, pkt, avail, 0, (struct sockaddr *) peer, &sinlen);
    outLen = amt > 0 ? amt : 0;
    // todo errs
    code = MOZQUIC_OK;
  }
  if (code != MOZQUIC_OK) {
    return code;
  }

  return MOZQUIC_OK;
}

uint32_t
MozQuic::Transmit(unsigned char *pkt, uint32_t len, struct sockaddr_in *explicitPeer)
{
  // this would be a reasonable place to insert a queuing layer that
  // thought about cong control, flow control, priority, and pacing
  
  if (mTransmitCallback) {
    return mTransmitCallback(mClosure, pkt, len); // todo take peer arg
  }
  int rv;
  struct sockaddr_in *peer = explicitPeer ? explicitPeer : &mPeer;
  if (mIsChild || explicitPeer) {
    rv = sendto(mFD, pkt, len, 0,
                (struct sockaddr *)peer, sizeof(struct sockaddr_in));
  } else {
    rv = send(mFD, pkt, len, 0);
  }

  if (rv == -1) {
    Log((char *)"Sending error in transmit");
  }
  
  return MOZQUIC_OK;
}

void
MozQuic::RaiseError(uint32_t e, char *reason)
{
  Log(reason);
  fprintf(stderr,"MozQuic Logger :%u:\n", e);
  if (mErrorCB) {
    mErrorCB(mClosure, e, reason);
  }
}

// this is called by the application when the application is handling
// the TLS stream (so that it can do more sophisticated handling
// of certs etc like gecko PSM does). The app is providing the
// client hello
void
MozQuic::HandshakeOutput(unsigned char *buf, uint32_t datalen)
{
  mStream0->Write(buf, datalen);
}

// this is called by the application when the application is handling
// the TLS stream (so that it can do more sophisticated handling
// of certs etc like gecko PSM does). The app is providing the
// client hello
void
MozQuic::HandshakeComplete(uint32_t code)
{
  if (!mHandshakeInput) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"not using handshaker api");
    return;
  }
  if (mConnectionState != CLIENT_STATE_1RTT) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"Handshake complete in wrong state");
    return;
  }
  mConnectionState = CLIENT_STATE_CONNECTED;
}

int
MozQuic::Client1RTT() 
{
  if (!mHandshakeInput) {
    // todo handle doing this internally
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"need handshaker");
    return MOZQUIC_ERR_GENERAL;
  }

  if (!mStream0->Empty()) {
    // Server Reply is available
    unsigned char buf[kMozQuicMSS];
    uint32_t amt = 0;
    bool fin = false;
    
    uint32_t code = mStream0->Read(buf, kMozQuicMSS, amt, fin);
    if (code != MOZQUIC_OK) {
      return code;
    }
    if (amt > 0) {
      // called to let the app know that the server hello is ready
      mHandshakeInput(mClosure, buf, amt);
    }
  }
  return MOZQUIC_OK;
}

int
MozQuic::Server1RTT() 
{
  if (mHandshakeInput) {
    // todo handle app-security on server side
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"need handshaker");
    return MOZQUIC_ERR_GENERAL;
  }

  if (!mStream0->Empty()) {
    uint32_t code = mNSSHelper->DriveHandshake();
    if (code != MOZQUIC_OK) {
      RaiseError(code, (char *) "server 1rtt handshake failed");
      return code;
    }
    if (mNSSHelper->IsHandshakeComplete()) {
      mConnectionState = SERVER_STATE_CONNECTED;
    }
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::ProcessVersionNegotiation(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  // check packet num and version
  assert(pkt[0] & 0x80);
  assert((pkt[0] & ~0x80) == PACKET_TYPE_VERSION_NEGOTIATION);
  assert(pktSize >= 17);
  assert(mIsClient);
  unsigned char *framePtr = pkt + 17;

  if (mConnectionState != CLIENT_STATE_1RTT) {
    // todo this isn't really strong enough (mvp)
    // any packet recvd on this conn would invalidate
    return MOZQUIC_ERR_VERSION;
  }
      
  if (header.mVersion != mVersion) {
    // this was supposedly copied from client - so this isn't a match
    return MOZQUIC_ERR_VERSION;
  }
  
  // essentially this is an ack of client_initial using the packet #
  // in the header as the ack, so need to find that on the unacked list
  std::unique_ptr<MozQuicStreamChunk> tmp(nullptr);
  for (auto i = mUnAcked.begin(); i != mUnAcked.end(); i++) {
    if ((*i)->mPacketNumber == header.mPacketNumber) {
      tmp = std::unique_ptr<MozQuicStreamChunk>(new MozQuicStreamChunk(*(*i)));
      mUnAcked.clear();
      break;
    }
  }
  if (!tmp) {
    // packet num was supposedly copied from client - so no match
    return MOZQUIC_ERR_VERSION;
  }

  uint16_t numVersions = ((pktSize) - 17) / 4;
  for (uint16_t i = 0; i < numVersions; i++) {
    uint32_t possibleVersion;
    memcpy((unsigned char *)&possibleVersion, framePtr, 4);
    framePtr += 4;
    possibleVersion = ntohl(possibleVersion);
    // todo this does not give client any preference
    if (VersionOK(possibleVersion)) {
      mVersion = possibleVersion;
      mConnectionID = header.mConnectionID;
      fprintf(stderr, "negotiated version %X\n", mVersion);
      DoWriter(tmp);
      return MOZQUIC_OK;
    }
  }
  RaiseError(MOZQUIC_ERR_VERSION, (char *)"unable to negotiate version");
  return MOZQUIC_ERR_VERSION;
}

int
MozQuic::ProcessServerCleartext(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  // cleartext is always in long form
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == PACKET_TYPE_SERVER_CLEARTEXT);
  assert(pktSize >= 17);

  if (header.mVersion != mVersion) {
    Log((char *)"wrong version");
    return MOZQUIC_ERR_GENERAL;
    // this should not abort session as its
    // not authenticated
  }

  mReceivedServerClearText = true;
  mConnectionID = header.mConnectionID;
  // todo log change
  
  return IntakeStream0(pkt, pktSize);
}

void
MozQuic::ProcessAck(FrameHeaderData &result, unsigned char *framePtr)
{
  // frameptr points to the beginning of the ackblock section
  // we have already runtime tested that there is enough data there
  // to read the ackblocks and the tsblocks
  assert (result.mType == FRAME_TYPE_ACK);
  uint16_t iters = 0;

  std::array<std::pair<uint64_t, uint64_t>, 257> ackStack;

  uint64_t largestAcked = result.u.mAck.mLargestAcked;
  do {
    uint64_t extra = 0;
    const uint8_t blockLengthLen = result.u.mAck.mAckBlockLengthLen;
    memcpy(((char *)&extra) + (8 - blockLengthLen), framePtr, blockLengthLen);
    extra = ntohll(extra);
    framePtr += blockLengthLen;

    fprintf(stderr,"ACK RECVD FOR %lX -> %lX\n",
            largestAcked - extra, largestAcked);
    // form a stack here so we can process them starting at the
    // lowest packet number, which is how mUnAcked is ordered and
    // do it all in one pass
    assert(iters < 257);
    ackStack[iters] =
      std::pair<uint64_t, uint64_t>(largestAcked - extra, extra + 1);

    largestAcked--;
    largestAcked -= extra;
    if (iters++ == result.u.mAck.mNumBlocks) {
      break;
    }
    uint8_t gap = *framePtr;
    largestAcked -= gap;
    framePtr++;
  } while (1);

  auto i = mUnAcked.begin();
  for (; iters > 0; --iters) {
    uint64_t seeking = ackStack[iters - 1].first;
    uint64_t stopSeeking = seeking + ackStack[iters - 1].second;
    for (; seeking < stopSeeking; seeking++) {

      // skip over stuff that is too low
      for (; (i != mUnAcked.end()) && ((*i)->mPacketNumber < seeking); i++);

      if ((i == mUnAcked.end()) || ((*i)->mPacketNumber > seeking)) {
        fprintf(stderr,"ACK'd packet not found for %lX\n", seeking);
      } else {
        assert ((*i)->mPacketNumber == seeking);
        fprintf(stderr,"ACK'd packet found for %lX\n", seeking);
        i = mUnAcked.erase(i);
      }
    }
  }
  
  // todo read the timestamps
  // and obviously todo feed the times into congestion control
}

int
MozQuic::IntakeStream0(unsigned char *pkt, uint32_t pktSize) 
{
  // todo this assumes long header
  // used by both client and server
  unsigned char *endpkt = pkt + pktSize;
  uint32_t ptr = 17;

  pktSize -= 8; // checksum. todo mvp verify
  bool sendAck = false;

  while (ptr < pktSize) {
    FrameHeaderData result(pkt + ptr, pktSize - ptr, this);
    if (result.mValid != MOZQUIC_OK) {
      return result.mValid;
    }
    ptr += result.mFrameLen;
    if (result.mType == FRAME_TYPE_PADDING) {
      continue;
    } else if (result.mType == FRAME_TYPE_STREAM) {
      sendAck = true;
      if (result.u.mStream.mStreamID != 0) {
        RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream 0 expected");
        return MOZQUIC_ERR_GENERAL;
      }
      // todo, ultimately the stream chunk could hold references to
      // the packet buffer and ptr into it for zero copy
      
      // parser checked for this, but jic
      assert(pkt + ptr + result.u.mStream.mDataLen <= endpkt);
      std::unique_ptr<MozQuicStreamChunk>
        tmp(new MozQuicStreamChunk(result.u.mStream.mStreamID,
                                   result.u.mStream.mOffset,
                                   pkt + ptr,
                                   result.u.mStream.mDataLen,
                                   result.u.mStream.mFinBit));
      mStream0->Supply(tmp);
      ptr += result.u.mStream.mDataLen;
    } else if (result.mType == FRAME_TYPE_ACK) {
      // ptr now points at ack block section
      uint32_t ackBlockSectionLen =
        result.u.mAck.mAckBlockLengthLen +
        (result.u.mAck.mNumBlocks * (result.u.mAck.mAckBlockLengthLen + 1));
      uint32_t timestampSectionLen = result.u.mAck.mNumTS * 3;
      if (timestampSectionLen) {
        timestampSectionLen += 2; // the first one is longer
      }
      assert(pkt + ptr + ackBlockSectionLen + timestampSectionLen <= endpkt);
      ProcessAck(result, pkt + ptr);
      ptr += ackBlockSectionLen;
      ptr += timestampSectionLen;
    } else {
      sendAck = true;
      RaiseError(MOZQUIC_ERR_GENERAL, (char *) "unexpected frame type");
      return MOZQUIC_ERR_GENERAL;
    }
    assert(pkt + ptr <= endpkt);
  }

  if (sendAck) {
    MaybeSendAck();
  }
  return MOZQUIC_OK;
}

MozQuic *
MozQuic::Accept(struct sockaddr_in *clientAddr)
{
  MozQuic *child = new MozQuic(mHandleIO);
  child->mIsChild = true;
  child->mIsClient = false;
  memcpy(&child->mPeer, clientAddr, sizeof (struct sockaddr_in));
  child->mFD = mFD;
  
  child->mStream0.reset(new MozQuicStreamPair(0, child));
  do {
    for (int i=0; i < 4; i++) {
      child->mConnectionID = child->mConnectionID << 16;
      child->mConnectionID = child->mConnectionID | (random() & 0xffff);
    }
  } while (mConnectionHash.count(child->mConnectionID) != 0);
      
  for (int i=0; i < 2; i++) {
    child->mNextPacketNumber = child->mNextPacketNumber << 16;
    child->mNextPacketNumber = child->mNextPacketNumber | (random() & 0xffff);
  }
  child->mNextPacketNumber &= 0x7fffffff; // 31 bits
  child->mOriginalPacketNumber = child->mNextPacketNumber;

  assert(!mHandshakeInput);
  if (!mHandshakeInput) {
    child->mNSSHelper.reset(new NSSHelper(child, mOriginName.get()));
  }
  child->mVersion = mVersion;
  
  mConnectionHash.insert( { child->mConnectionID, child });
  return child;
}

bool
MozQuic::VersionOK(uint32_t proposed)
{
  if (proposed == kMozQuicVersion1 ||
      proposed == kMozQuicIetfID3) {
    return true;
  }
  return false;
}

uint32_t
MozQuic::GenerateVersionNegotiation(LongHeaderData &clientHeader, struct sockaddr_in *peer)
{
  assert(!mIsChild);
  assert(!mIsClient);
  unsigned char pkt[kMozQuicMTU];
  uint32_t tmp32;
  uint64_t tmp64;

  pkt[0] = 0x80 | PACKET_TYPE_VERSION_NEGOTIATION;
  // lets use the client connID for now, we can change it in server_cleartext
  tmp64 = htonll(clientHeader.mConnectionID);
  memcpy(pkt + 1, &tmp64, 8);

  // 32 packet number echo'd from client
  tmp32 = htonl(clientHeader.mPacketNumber);
  memcpy(pkt + 9, &tmp32, 4);
  
  // 32 version echo'd from client
  tmp32 = htonl(clientHeader.mVersion);
  memcpy(pkt + 13, &tmp32, 4);
  
  // list of versions
  unsigned char *framePtr = pkt + 17;
  assert(((framePtr + 4) - pkt) <= kMozQuicMTU);
  tmp32 = htonl(kMozQuicVersionGreaseS);
  memcpy (framePtr, &tmp32, 4);
  framePtr += 4;
  assert(((framePtr + 4) - pkt) <= kMozQuicMTU);
  tmp32 = htonl(kMozQuicIetfID3);
  memcpy (framePtr, &tmp32, 4);
  framePtr += 4;
  assert(((framePtr + 4) - pkt) <= kMozQuicMTU);
  tmp32 = htonl(kMozQuicVersion1);
  memcpy (framePtr, &tmp32, 4);
  framePtr += 4;

  // no checksum
  fprintf(stderr,"TRANSMIT VERSION NEGOTITATION\n");
  return Transmit(pkt, framePtr - pkt, peer);
}

int
MozQuic::ProcessClientInitial(unsigned char *pkt, uint32_t pktSize,
                              struct sockaddr_in *clientAddr,
                              LongHeaderData &header,
                              MozQuic **childSession)
{
  // this is always in long header form
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_INITIAL);
  assert(pktSize >= 17);
  assert(!mIsChild);

  *childSession = nullptr;
  if (mConnectionState != SERVER_STATE_LISTEN) { // todo rexmit right?
    return MOZQUIC_OK;
  }
  if (mIsClient) {
    return MOZQUIC_ERR_GENERAL;
  }

  if (pktSize < kMozQuicMTU) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"client initial packet too small");
    return MOZQUIC_ERR_GENERAL;
  }
  
  // todo - its not legal to send this across two packets, but it could
  // be dup'd or retrans'd..  should not do accept, it should find the session

  mVersion = header.mVersion;

  MozQuic *child = Accept(clientAddr);
  child->mConnectionState = SERVER_STATE_1RTT;
  child->IntakeStream0(pkt, pktSize);
  assert(mNewConnCB); // todo handle err
  mNewConnCB(mClosure, child);
  *childSession = child;
  return MOZQUIC_OK;
}

int
MozQuic::ProcessClientCleartext(unsigned char *pkt, uint32_t pktSize, LongHeaderData &header)
{
  // this is always with a long header
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_CLEARTEXT);
  assert(pktSize >= 17);
  assert(mIsChild);

  if (mConnectionState != SERVER_STATE_1RTT) { // todo rexmit right?
    return MOZQUIC_ERR_GENERAL;
  }
  assert(!mIsClient);
  assert(mStream0);

  if (header.mVersion != mVersion) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"version mismatch");
    return MOZQUIC_ERR_GENERAL;
  }
  
  return IntakeStream0(pkt, pktSize);
}

uint32_t
MozQuic::FlushStream0()
{
  if (mUnWritten.empty()) {
    return MOZQUIC_OK;
  }
      
  unsigned char pkt[kMozQuicMTU];
  unsigned char *endpkt = pkt + kMozQuicMTU;
  uint32_t tmp32;

  // section 5.4.1 of transport
  // long form header 17 bytes
  pkt[0] = 0x80;
  if (ServerState()) {
    pkt[0] |= PACKET_TYPE_SERVER_CLEARTEXT;
  } else {
    pkt[0] |= mReceivedServerClearText ? PACKET_TYPE_CLIENT_CLEARTEXT : PACKET_TYPE_CLIENT_INITIAL;
  }

  // todo store a big endian version of this
  uint64_t connID = htonll(mConnectionID);
  memcpy(pkt + 1, &connID, 8);
  
  tmp32 = htonl(mNextPacketNumber);
  memcpy(pkt + 9, &tmp32, 4);
  tmp32 = htonl(mVersion);
  memcpy(pkt + 13, &tmp32, 4);

  unsigned char *framePtr = pkt + 17;

  auto iter = mUnWritten.begin();
  while (iter != mUnWritten.end()) {
    if ((*iter)->mStreamID == 0) {
      uint32_t room = endpkt - framePtr - 8; // the last 8 are for checksum
      if (room < 9) {
        break; // 8 header bytes and 1 data byte
      }

      // stream header is 8 bytes long
      // 1 type + 2 bytes of len, 1 stream id,
      // 4 bytes of offset. That's type 0xd8
      framePtr[0] = 0xd8;
      uint16_t tmp16 = (*iter)->mLen;
      // todo check range.. that's really wrong as its 32
      tmp16 = htons(tmp16);
      memcpy(framePtr + 1, &tmp16, 2);
      framePtr[3] = 0; // stream 0

      // 4 bytes of offset is normally a waste, but it just comes
      // out of padding
      tmp32 = (*iter)->mOffset;
      tmp32 = htonl(tmp32);
      memcpy(framePtr + 4, &tmp32, 4);
      framePtr += 8;

      room -= 8;
      if (room < (*iter)->mLen) {
        // we need to split this chunk. its too big
        // todo iterate on them all instead of doing this n^2
        // as there is a copy involved
        std::unique_ptr<MozQuicStreamChunk>
          tmp(new MozQuicStreamChunk((*iter)->mStreamID,
                                     (*iter)->mOffset + room,
                                     (*iter)->mData.get() + room,
                                     (*iter)->mLen - room,
                                     (*iter)->mFin));
        (*iter)->mLen = room;
        (*iter)->mFin = false;
        tmp16 = (*iter)->mLen;
        tmp16 = htons(tmp16);
        memcpy(framePtr - 7, &tmp16, 2);
        auto iterReg = iter++;
        mUnWritten.insert(iter, std::move(tmp));
        iter = iterReg;
      }
      assert(room >= (*iter)->mLen);

      memcpy(framePtr, (*iter)->mData.get(), (*iter)->mLen);
      framePtr += (*iter)->mLen;

      (*iter)->mPacketNumber = mNextPacketNumber;
      (*iter)->mTransmitTime = Timestamp();
      (*iter)->mTransmitKeyPhase = QuicKeyPhaseUnprotected; // only for stream 0 todo
      (*iter)->mRetransmitted = false;
      
      // move it to the unacked list
      std::unique_ptr<MozQuicStreamChunk> x(std::move(*iter));
      mUnAcked.push_back(std::move(x));
      iter = mUnWritten.erase(iter);
    } else {
      iter++;
    }
  }

  if (framePtr != (pkt + 17)) {
    // then padding as needed up to 1272 on client_initial
    uint32_t finalLen;

    if ((pkt[0] & 0x7f) == PACKET_TYPE_CLIENT_INITIAL) {
      finalLen = kMozQuicMTU;
    } else {
      uint32_t room = endpkt - framePtr - 8; // the last 8 are for checksum
      uint32_t used;
      if (AckPiggyBack(framePtr, room, QuicKeyPhaseUnprotected, used) == MOZQUIC_OK) {
        framePtr += used;
      }
      finalLen = ((framePtr - pkt) + 8);
    }

    uint32_t paddingNeeded = finalLen - 8 - (framePtr - pkt);
    memset (framePtr, 0, paddingNeeded);
    framePtr += paddingNeeded;

    // then 8 bytes of checksum on cleartext packets
    assert (FNV64size == 8);
    if (FNV64block(pkt, finalLen - FNV64size, framePtr) != 0) {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *)"hash err");
      return MOZQUIC_ERR_GENERAL;
    }
    uint32_t code = Transmit(pkt, finalLen, nullptr);
    if (code != MOZQUIC_OK) {
      return code;
    }
    fprintf(stderr,"TRANSMIT %lX\n", mNextPacketNumber);
    mNextPacketNumber++;
    // each member of the list needs to 
  }

  if (iter != mUnWritten.end()) {
    return FlushStream0(); // todo mvp this is broken with non stream 0 pkts
  }
  return MOZQUIC_OK;
}

uint64_t
MozQuic::Timestamp()
{
  // ms since epoch
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

uint32_t
MozQuic::Flush()
{
  // todo mvp obviously have to deal with more than this :)
  return FlushStream0();
}

uint32_t
MozQuic::DoWriter(std::unique_ptr<MozQuicStreamChunk> &p)
{

  // this data gets queued to unwritten and framed and
  // transmitted after prioritization by flush()

  // obviously have to deal with more than this :)
  assert (p->mTransmitKeyPhase == QuicKeyPhaseUnprotected);

  mUnWritten.push_back(std::move(p));

  return MOZQUIC_OK;
}

int32_t
MozQuic::NSSInput(void *buf, int32_t amount)
{
  if (mStream0->Empty()) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
    
  // client part of handshake is available in stream 0,
  // feed it to nss via the return code of this fx
  uint32_t amt = 0;
  bool fin = false;
    
  uint32_t code = mStream0->Read((unsigned char *)buf,
                                 amount, amt, fin);
  if (code != MOZQUIC_OK) {
    PR_SetError(PR_IO_ERROR, 0);
    return -1;
  }
  if (amt > 0) {
    return amt;
  }
  if (fin) {
    return 0;
  }
  PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
  return -1;
}

int32_t
MozQuic::NSSOutput(const void *buf, int32_t amount)
{
  // nss has produced some server output e.g. server hello
  // we need to put it into stream 0 so that it can be
  // written on the network
  return mStream0->Write((const unsigned char *)buf, amount);
}

uint32_t
MozQuic::RetransmitTimer()
{
  if (mUnAcked.empty()) {
    return MOZQUIC_OK;
  }

  // this is a crude stand in for reliability until we get a real loss
  // recovery system built
  uint64_t now = Timestamp();
  uint64_t discardEpoch = now - kForgetUnAckedThresh;

  for (auto i = mUnAcked.begin(); i != mUnAcked.end(); i++) {

    // just a linear backoff for now
    uint64_t retransEpoch =
      now - (kRetransmitThresh * (*i)->mTransmitCount);

    if ((*i)->mTransmitTime > retransEpoch) {
      break;
    }
    if (((*i)->mTransmitTime <= discardEpoch) && (*i)->mRetransmitted) {
      // this is only on packets that we are keeping around for timestamp purposes
      fprintf(stderr,"old unacked packet forgotten %lX\n",
              (*i)->mPacketNumber);
      assert(!(*i)->mData);
      i = mUnAcked.erase(i);
    } else if (!(*i)->mRetransmitted) {
      assert((*i)->mData);
      fprintf(stderr,"data for packet %lX retransmitted\n",
              (*i)->mPacketNumber);
      (*i)->mRetransmitted = true;

      // the ctor steals the data pointer
      std::unique_ptr<MozQuicStreamChunk> tmp(new MozQuicStreamChunk(*(*i)));
      assert(!(*i)->mData);
      DoWriter(tmp);
    }
  }

  return MOZQUIC_OK;
}

MozQuic::FrameHeaderData::FrameHeaderData(unsigned char *pkt, uint32_t pktSize, MozQuic *logger)
{
  memset(&u, 0, sizeof (u));
  mValid = MOZQUIC_ERR_GENERAL;

  unsigned char type = pkt[0];
  unsigned char *framePtr = pkt + 1;
  if ((type & FRAME_MASK_STREAM) == FRAME_TYPE_STREAM) {
    mType = FRAME_TYPE_STREAM;

    u.mStream.mFinBit = (type & 0x20);

    bool lenBit = (type & 0x10);
    uint32_t lenLen = lenBit ? 2 : 0;
    uint32_t offsetLen = (type & 0x0c) >> 2;
    if (offsetLen == 1) {
      offsetLen = 2;
    } else if (offsetLen == 2) {
      offsetLen = 4;
    } else if (offsetLen == 3) {
      offsetLen = 8;
    }

    uint32_t idLen = (type & 0x03) + 1;
    uint32_t bytesNeeded = 1 + lenLen + idLen + offsetLen;
    if (bytesNeeded > pktSize) {
      logger->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream frame header short");
      return;
    }

    if (lenBit) {
      memcpy (&u.mStream.mDataLen, framePtr, 2);
      framePtr += 2;
      u.mStream.mDataLen = ntohs(u.mStream.mDataLen);
    } else {
      u.mStream.mDataLen = pktSize - bytesNeeded;
    }
    // todo log frame len
    if (bytesNeeded + u.mStream.mDataLen > pktSize) {
      logger->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream frame data short");
      return;
    }

    memcpy(((char *)&u.mStream.mStreamID) + (4 - idLen), framePtr, idLen);
    framePtr += idLen;
    u.mStream.mStreamID = ntohl(u.mStream.mStreamID);

    memcpy(((char *)&u.mStream.mOffset) + (8 - offsetLen), framePtr, offsetLen);
    framePtr += offsetLen;
    u.mStream.mOffset = ntohll(u.mStream.mOffset);
    mValid = MOZQUIC_OK;
    mFrameLen = bytesNeeded;
    return;
  } else if ((type & FRAME_MASK_ACK) == FRAME_TYPE_ACK) {
    mType = FRAME_TYPE_ACK;
    uint8_t numBlocks = (type & 0x10) ? 1 : 0; // N bit
    uint32_t ackedLen = (type & 0x0c) >> 2; // LL bits
    if (ackedLen == 0) {
      ackedLen = 1;
    } else if (ackedLen == 1) {
      ackedLen = 2;
    } else if (ackedLen == 2) {
      ackedLen = 4;
    } else { // (ackedLen == 3)
      ackedLen = 6;
    }

    u.mAck.mAckBlockLengthLen = (type & 0x03); // MM bits
    if (u.mAck.mAckBlockLengthLen == 0) {
      u.mAck.mAckBlockLengthLen = 1;
    } else if (u.mAck.mAckBlockLengthLen == 1) {
      u.mAck.mAckBlockLengthLen = 2;
    } else if (u.mAck.mAckBlockLengthLen == 2) {
      u.mAck.mAckBlockLengthLen = 4;
    } else { // u.mAck.mAckBlockLengthLen == 3
      u.mAck.mAckBlockLengthLen = 6;
    }

    uint16_t bytesNeeded = 1 + numBlocks + 1 + ackedLen + 2;
    if (bytesNeeded > pktSize) {
      logger->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame header short");
      return;
    }

    if (numBlocks) {
      u.mAck.mNumBlocks = framePtr[0];
      framePtr++;
    } else {
      u.mAck.mNumBlocks = 0;
    }
    u.mAck.mNumTS = framePtr[0];
    framePtr++;
    memcpy(((char *)&u.mAck.mLargestAcked) + (8 - ackedLen), framePtr, ackedLen);
    framePtr += ackedLen;
    u.mAck.mLargestAcked = ntohll(u.mAck.mLargestAcked); // todo mvp these are only the low bits

    memcpy(&u.mAck.mAckDelay, framePtr, 2);
    framePtr += 2;
    u.mAck.mAckDelay = ntohs(u.mAck.mAckDelay);
    bytesNeeded += u.mAck.mAckBlockLengthLen + // required First ACK Block
                   u.mAck.mNumBlocks * (1 + u.mAck.mAckBlockLengthLen); // additional ACK Blocks
    if (u.mAck.mNumTS) {
      bytesNeeded += u.mAck.mNumTS * (1 + 2) + 2;
    }
    if (bytesNeeded > pktSize) {
      logger->RaiseError(MOZQUIC_ERR_GENERAL, (char *) "ack frame header short");
      return;
    }
    mValid = MOZQUIC_OK;
    mFrameLen = framePtr - pkt;
    return;
  } else {
    switch(type) {

    case FRAME_TYPE_PADDING:
      mType = FRAME_TYPE_PADDING;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PADDING_LENGTH;
      return;

    case FRAME_TYPE_RST_STREAM:
      if (pktSize < FRAME_TYPE_RST_STREAM_LENGTH) {
        logger->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "RST_STREAM frame length expected");
        return;
      }

      mType = FRAME_TYPE_RST_STREAM;

      memcpy(&u.mRstStream.mErrorCode, framePtr, 4);
      u.mRstStream.mErrorCode = ntohl(u.mRstStream.mErrorCode);
      framePtr += 4;
      memcpy(&u.mRstStream.mStreamID, framePtr, 4);
      u.mRstStream.mStreamID = ntohl(u.mRstStream.mStreamID);
      framePtr += 4;
      memcpy(&u.mRstStream.mFinalOffset, framePtr, 8);
      u.mRstStream.mFinalOffset = ntohll(u.mRstStream.mFinalOffset);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_RST_STREAM_LENGTH;
      return;

    case FRAME_TYPE_CLOSE:
      if (pktSize < FRAME_TYPE_CLOSE_LENGTH) {
        logger->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "CONNECTION_CLOSE frame length expected");
        return;
      }

      mType = FRAME_TYPE_CLOSE;

      memcpy(&u.mClose.mErrorCode, framePtr, 4);
      u.mClose.mErrorCode = ntohl(u.mClose.mErrorCode);
      framePtr += 4;
      uint16_t len;
      memcpy(&len, framePtr, 2);
      len = ntohs(len);
      framePtr += 2;
      if (len) {
        if (pktSize < ((uint32_t)FRAME_TYPE_CLOSE_LENGTH + len)) {
          logger->RaiseError(MOZQUIC_ERR_GENERAL,
                     (char *) "CONNECTION_CLOSE frame length expected");
          return;
        }
        // Log error!
        framePtr[len-1] = '\0';// Make sure it is 0-ended TODO:
        logger->Log((char *)framePtr);
      }
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_CLOSE_LENGTH + len;
      return;

    case FRAME_TYPE_GOAWAY:
      if (pktSize < FRAME_TYPE_GOAWAY_LENGTH) {
        logger->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "GOAWAY frame length expected");
        return;
      }

      mType = FRAME_TYPE_GOAWAY;

      memcpy(&u.mGoaway.mClientStreamID, framePtr, 4);
      u.mGoaway.mClientStreamID = ntohl(u.mGoaway.mClientStreamID);
      framePtr += 4;
      memcpy(&u.mGoaway.mServerStreamID, framePtr, 4);
      u.mGoaway.mServerStreamID = ntohl(u.mGoaway.mServerStreamID);
      framePtr += 4;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_GOAWAY_LENGTH;
      return;

    case FRAME_TYPE_MAX_DATA:
      if (pktSize < FRAME_TYPE_MAX_DATA_LENGTH) {
        logger->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "MAX_DATA frame length expected");
        return;
      }

      mType = FRAME_TYPE_MAX_DATA;

      memcpy(&u.mMaxData.mMaximumData, framePtr, 8);
      u.mMaxData.mMaximumData = ntohll(u.mMaxData.mMaximumData);
      mValid = MOZQUIC_OK;
      mFrameLen =  FRAME_TYPE_MAX_DATA_LENGTH;
      return;

    case FRAME_TYPE_MAX_STREAM_DATA:
      if (pktSize < FRAME_TYPE_MAX_STREAM_DATA_LENGTH) {
        logger->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "MAX_STREAM_DATA frame length expected");
        return;
      }

      mType = FRAME_TYPE_MAX_STREAM_DATA;

      memcpy(&u.mMaxStreamData.mStreamID, framePtr, 4);
      u.mMaxStreamData.mStreamID = ntohl(u.mMaxStreamData.mStreamID);
      framePtr += 4;
      memcpy(&u.mMaxStreamData.mMaximumStreamData, framePtr, 8);
      u.mMaxStreamData.mMaximumStreamData =
        ntohll(u.mMaxStreamData.mMaximumStreamData);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_MAX_STREAM_DATA_LENGTH;
      return;

    case FRAME_TYPE_MAX_STREAM_ID:
      if (pktSize < FRAME_TYPE_MAX_STREAM_ID_LENGTH) {
        logger->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "MAX_STREAM_ID frame length expected");
        return;
      }

      mType = FRAME_TYPE_MAX_STREAM_ID;

      memcpy(&u.mMaxStreamID.mMaximumStreamID, framePtr, 4);
      u.mMaxStreamID.mMaximumStreamID =
        ntohl(u.mMaxStreamID.mMaximumStreamID);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_MAX_STREAM_ID_LENGTH;
      return;

    case FRAME_TYPE_PING:
      mType = FRAME_TYPE_PING;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_PING_LENGTH;
      return;

    case FRAME_TYPE_BLOCKED:
      mType = FRAME_TYPE_BLOCKED;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_BLOCKED_LENGTH;
      return;

    case FRAME_TYPE_STREAM_BLOCKED:
      if (pktSize < FRAME_TYPE_STREAM_BLOCKED_LENGTH) {
        logger->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "STREAM_BLOCKED frame length expected");
        return;
      }

      mType = FRAME_TYPE_STREAM_BLOCKED;

      memcpy(&u.mStreamBlocked.mStreamID, framePtr, 4);
      u.mStreamBlocked.mStreamID = ntohl(u.mStreamBlocked.mStreamID);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_STREAM_BLOCKED_LENGTH;
      return;

    case FRAME_TYPE_STREAM_ID_NEEDED:
      mType = FRAME_TYPE_STREAM_ID_NEEDED;
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_STREAM_ID_NEEDED_LENGTH;
      return;

    case FRAME_TYPE_NEW_CONNECTION_ID:
      if (pktSize < FRAME_TYPE_NEW_CONNECTION_ID_LENGTH) {
        logger->RaiseError(MOZQUIC_ERR_GENERAL,
                   (char *) "NEW_CONNECTION_ID frame length expected");
        return;
      }

      mType = FRAME_TYPE_NEW_CONNECTION_ID;

      memcpy(&u.mNewConnectionID.mSequence, framePtr, 2);
      u.mNewConnectionID.mSequence = ntohs(u.mNewConnectionID.mSequence);
      framePtr += 2;
      memcpy(&u.mNewConnectionID.mConnectionID, framePtr, 8);
      u.mNewConnectionID.mConnectionID =
        ntohll(u.mNewConnectionID.mConnectionID);
      mValid = MOZQUIC_OK;
      mFrameLen = FRAME_TYPE_NEW_CONNECTION_ID_LENGTH;
      return;

    default:
      assert(false);
    }
  }
  mValid = MOZQUIC_OK;
}

MozQuic::LongHeaderData::LongHeaderData(unsigned char *pkt, uint32_t pktSize)
{
  // these fields are all version independent - though the interpretation
  // of type is not.
  assert(pktSize >= 17);
  assert(pkt[0] & 0x80);
  mType = static_cast<enum LongHeaderType>(pkt[0] & ~0x80);
  memcpy(&mConnectionID, pkt + 1, 8);
  mConnectionID = ntohll(mConnectionID);
  memcpy(&mPacketNumber, pkt + 9, 4);
  mPacketNumber = ntohl(mPacketNumber);
  memcpy(&mVersion, pkt + 13, 4);
  mVersion = ntohl(mVersion);
}

}

