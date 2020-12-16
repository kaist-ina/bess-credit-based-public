#include "xpass_core.h"
#include "../worker.h"
#include "../utils/udp.h"
#include <iomanip>

#define TCP_DEBUG 0
#define CHECKSUM_OFFLOAD 1
#define SKIP_RX_CHECKSUM 0
#define OPTIMIZE_FLOW_ALLOC 0
// __thread Worker current_worker;

const uint64_t CREDIT_RESPONSE_TIMEOUT = 1000000000ULL; // ns
const uint64_t CREDIT_STOP_SEND_TIMEOUT =  100000000ULL; // ns// 1000000ULL; // ns
const uint64_t CREDIT_REQUEST_TIMEOUT =  1000000ULL; // ns// 1000000ULL; // ns

static inline void DoTcpChecksum(bess::Packet *pkt, Ipv4 *iph, Tcp *tcph) {
#if CHECKSUM_OFFLOAD
  pkt->setup_offload_tcp(iph, tcph);
#else
  iph->checksum = CalculateIpv4Checksum(*iph);
  tcph->checksum = CalculateIpv4TcpChecksum(*iph, *tcph);
#endif
}

static inline void DoUdpChecksum(bess::Packet *pkt, Ipv4 *iph, Udp *udph) {
#if CHECKSUM_OFFLOAD
  pkt->setup_offload_udp(iph, udph);
#else
  iph->checksum = CalculateIpv4Checksum(*iph);
  udph->checksum = CalculateIpv4UdpChecksum(*iph, *udph);
#endif
}

// Helper function implementations
void XPassCore::SetDSCP(Ipv4 *iph, int dscp) {
  if (dscp < 0 || dscp > 127) {
    LOG(INFO) << "[XPass Core] Tried to set invalid DSCP value";
    return;
  }

  iph->type_of_service = (dscp << 2) | (iph->type_of_service & 0x3);
}

NetworkFlow* XPassCore::FindForwardFlow(Ipv4 *iph, Tcp *tcph) {
  NetworkFlowKey nfk;
  nfk.src_ip = iph->src;
  nfk.dst_ip = iph->dst;
  nfk.src_port = tcph->src_port;
  nfk.dst_port = tcph->dst_port; 

  std::map<NetworkFlowKey, NetworkFlow*>::iterator it;
  it = flow_table.find(nfk);

  if(it != flow_table.end()) {
    return it->second;
  }

  return nullptr;
}

NetworkFlow* XPassCore::FindReverseFlow(Ipv4 *iph, Udp *udph) {
  NetworkFlowKey nfk;
  nfk.src_ip = iph->dst;
  nfk.dst_ip = iph->src;
  nfk.src_port = udph->dst_port;
  nfk.dst_port = udph->src_port; 

  std::map<NetworkFlowKey, NetworkFlow *>::iterator it;
  it = flow_table.find(nfk);

  if(it != flow_table.end()) {
    return it->second;
  }

  return nullptr;
}

NetworkFlow* XPassCore::FindReverseFlow(Ipv4 *iph, Tcp *tcph) {
  NetworkFlowKey nfk;
  nfk.src_ip = iph->dst;
  nfk.dst_ip = iph->src;
  nfk.src_port = tcph->dst_port;
  nfk.dst_port = tcph->src_port; 

  std::map<NetworkFlowKey, NetworkFlow *>::iterator it;
  it = flow_table.find(nfk);

  if(it != flow_table.end()) {
    return it->second;
  }

  return nullptr;
}

CommandResponse XPassCore::Init(const bess::pb::EmptyArg &) {
  LOG(INFO) << "Initializing XPassCore.";
  task_id_t tid;

  tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID)
    return CommandFailure(ENOMEM, "Context creation failed");
    
  tx_timing_wheel.Init(now());
  flow_slot = new NetworkFlow[MAX_NUM_FLOW];
  memset(flow_bitmap, 0, sizeof(flow_bitmap));
  flow_count = 0;
  flow_table.clear();

  return CommandSuccess();
}

void XPassCore::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  gate_idx_t incoming_gate = ctx->current_igate;

  switch (incoming_gate) {
    case IGATE_FROM_TX:
      ReceiveTx(ctx, batch);
      break;
    case IGATE_FROM_RX:
      ReceiveRx(ctx, batch);
      break;
    default:
      LOG(ERROR) << "[XpassCore] Invalid input gate.";
  }
}

// TX Path implementations
void XPassCore::ReceiveTx(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::XpassTcpOption;

  bess::PacketBatch *new_batch = ctx->task->AllocPacketBatch();
  int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    uint16_t tcp_payload_len, ip_payload_len;
    uint8_t ip_hdrlen, tcp_hdrlen;
    uint8_t *payload;
    bess::utils::XpassTcpOption xopt;
    Tcp *tcph;
    Ethernet *eth;
    Ipv4 *iph;
    NetworkFlow *flow;
    // bess::Packet *pkt_clone = bess::Packet::copy(pkt); // for testing purpose

    eth = pkt->head_data<Ethernet *>();
    if (eth->ether_type != be16_t(Ethernet::Type::kIpv4))
      goto bypass;
    iph = reinterpret_cast<Ipv4 *>(eth + 1);
    ip_hdrlen = (iph->header_length) << 2;
    if (iph->protocol != Ipv4::Proto::kTcp)
      goto bypass;

    assert(iph->length.value() >= ip_hdrlen);
    assert(ip_hdrlen >= sizeof(Ipv4));

    ip_payload_len = iph->length.value() - ip_hdrlen;
    tcph = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(iph) + ip_hdrlen);

    // Injecting TCP option
    tcp_hdrlen = (tcph->offset) << 2;
    tcp_payload_len = ip_payload_len - tcp_hdrlen;
    assert(ip_payload_len >= tcp_hdrlen);
    assert(tcp_hdrlen >= sizeof(Tcp));

    payload = reinterpret_cast<uint8_t *>(reinterpret_cast<uint8_t *>(tcph) + tcp_hdrlen);

    flow = FindForwardFlow(iph, tcph);
    if (!flow) {
      NetworkFlowKey new_key;
      new_key.setForward(iph, tcph);
      flow = AllocateFlow(new_key, ctx);
      flow->generateCreditTemplate(eth, iph, tcph);
      LOG(INFO) << "Detected a new flow!";
    }

    if (flow->bypass_)
      goto bypass;

    // Inject if SYN or Data
    if (tcp_payload_len || (tcph->flags & Tcp::Flag::kSyn)) {
#if TCP_DEBUG
      LOG(INFO) << "Sending Data len=" << tcp_payload_len
                << ", seq=" << tcph->seq_num.value()
                << ", ack=" << tcph->ack_num.value();
#endif
      if (tcp_hdrlen + sizeof(XpassTcpOption) > (0xFF << 2)) {
        // no more space for TCP header! what should we do?
        LOG(INFO) << "No more space for TCP header! hdrlen=" << tcp_hdrlen;
        ReceiveDataTx(flow, eth, iph, tcph);
        DoTcpChecksum(pkt, iph, tcph);
        goto bypass;
      }

      memset(&xopt.xpass, 0, sizeof(Xpass));
      xopt.xpass.packet_type = Xpass::kData;

      if (tcp_payload_len && pkt->data_off() >= sizeof(XpassTcpOption)) {
        // shift header to headroom
        uint8_t *prev_head = pkt->head_data<uint8_t *>();
        memmove(pkt->prepend(sizeof(XpassTcpOption)), prev_head, payload - prev_head); // bess::utils::Copy is not safe when mem range overlaps

        // recalculate header pos
        eth = reinterpret_cast<Ethernet *> (reinterpret_cast<uint8_t *>(eth) - sizeof(XpassTcpOption));
        iph = reinterpret_cast<Ipv4 *> (reinterpret_cast<uint8_t *>(iph) - sizeof(XpassTcpOption));
        tcph = reinterpret_cast<Tcp *> (reinterpret_cast<uint8_t *>(tcph) - sizeof(XpassTcpOption));
      } else {
        // prepare 16 bytes and allocate 16 bytes tcp option
        pkt->append(sizeof(XpassTcpOption));
        payload += sizeof(XpassTcpOption);
      }
      bess::utils::Copy(payload - sizeof(XpassTcpOption), &xopt, sizeof(XpassTcpOption));

      tcph->offset = (tcp_hdrlen + sizeof(XpassTcpOption)) >> 2;
      iph->length = be16_t(iph->length.value() + sizeof(XpassTcpOption));
      iph->type_of_service = (iph->type_of_service & 0x3) | (bess::utils::GDX_DSCP_PROACTIVE << 2);
    } else {
#if TCP_DEBUG      
      LOG(INFO) << "Sending ACK? len=" << tcp_payload_len
                << ", ack=" << tcph->ack_num.value()
                << ", seq=" << tcph->seq_num.value();
#endif
    }


    if (!tcp_payload_len && !(flow->queue_->cnt())) {
      // if ((tcph->offset << 2) < 20) {
      //   LOG(INFO) << "TCP invalid header detected at pre-bypass.";
      //   PrintArray(pkt->head_data(), pkt->total_len());
      //   LOG(INFO) << "====Injected Data====";
      //   PrintArray(pkt_clone->head_data(), pkt_clone->total_len());
      //   LOG(INFO) << "Detected tcp_hdrlen = " << tcp_hdrlen;
      //   LOG(INFO) << "Detected tcp_payload_len = " << tcp_payload_len;
      //   LOG(INFO) << "New offset = " << tcph->offset;
      // }
      ReceiveDataTx(flow, eth, iph, tcph);
      DoTcpChecksum(pkt, iph, tcph);
      goto bypass;
    }
    
    if (flow->queue_->full()) {
      LOG(INFO) << "Packet Loss!";
    }

    // add to queue, send credit request if needed
    // if ((tcph->offset << 2) < 20) {
    //   LOG(INFO) << "TCP invalid header detected before adding.";
    //   PrintArray(pkt->head_data(), pkt->total_len());
    // }
    flow->queue_->push_back(pkt);
    if (flow->credit_recv_state_ == XPASS_RECV_CLOSED || flow->credit_recv_state_ == XPASS_RECV_CREDIT_STOP_SENT) {
      LOG(INFO) << "Sending Credit Request!";
      flow->credit_recv_state_ = XPASS_RECV_CREDIT_REQUEST_SENT;
      flow->tmr_credit_request_timeout_ = now() + CREDIT_REQUEST_TIMEOUT;
      SendSingle(flow, CreateCreditRequest(flow));
    }
    // bess::Packet::Free(pkt_clone);
    // pkt_clone = nullptr;
    continue;

  bypass:
    // bess::Packet::Free(pkt_clone);
    // pkt_clone = nullptr;
    new_batch->add(pkt);
    if((size_t)new_batch->cnt() >= bess::PacketBatch::kMaxBurst) {
      RunChooseModule(ctx, OGATE_TO_NIC, new_batch);
      new_batch = ctx->task->AllocPacketBatch();
      new_batch->clear();
    }
  }

  RunChooseModule(ctx, OGATE_TO_NIC, new_batch);
}


bool XPassCore::ReceiveDataTx(NetworkFlow *flow, Ethernet *eth, Ipv4 *iph, Tcp *tcph) {
  (void)eth;
  (void)iph;

  if ((tcph->flags & Tcp::Flag::kSyn) && !(tcph->flags & Tcp::Flag::kAck)) {
    ReceiveSynTx(flow);
  } else if ((tcph->flags & Tcp::Flag::kSyn) &&
             (tcph->flags & Tcp::Flag::kAck)) {
    ReceiveSynAckTx(flow);
  } else if ((tcph->flags & Tcp::Flag::kRst)) {
    flow->SetTCPState(XPASS_TCP_CLOSED);
  } else if ((tcph->flags & Tcp::Flag::kFin)) {
    // FIN
    // LOG(INFO) << "Detect FIN Tx! state=" << flow->tcp_state_;
    if (flow->tcp_state_ == XPASS_TCP_ESTABLISHED) {
      flow->SetTCPState(XPASS_TCP_FIN_WAIT); // active
    } else if (flow->tcp_state_ == XPASS_TCP_CLOSE_WAIT) {
      flow->SetTCPState(XPASS_TCP_LAST_ACK); // passive
    }
  } else if (tcph->flags & Tcp::Flag::kAck) {
    ProcessAckTx(flow);
  } 

  if (flow->tcp_state_ == XPASS_TCP_CLOSED) {
    LOG(INFO) << "TCP closed, destroying flow";
    if (flow->credit_recv_state_ == XPASS_RECV_CREDIT_RECEIVING) {
      SendSingle(flow, CreateCreditStop(flow));
    }
    EvictFlow(flow);
    return false;
  }
  return true;
}

void XPassCore::ReceiveSynTx(NetworkFlow *flow) {
  // Got Syn from TX module
  flow->SetTCPState(XPASS_TCP_SYN_SENT);
  LOG(INFO) << "Sending SYN";
}

void XPassCore::ReceiveSynAckTx(NetworkFlow *flow) {
  if (flow->tcp_state_ == XPASS_TCP_SYN_RECEIVED) {
    flow->SetTCPState(XPASS_TCP_SYNACK_SENT);
    LOG(INFO) << "Sending SYNACK";
  }
}

void XPassCore::ProcessAckTx(NetworkFlow *flow) {
  if (flow->tcp_state_ == XPASS_TCP_SYNACK_RECEIVED) {
    flow->SetTCPState(XPASS_TCP_ESTABLISHED);
    LOG(INFO) << "Connection Established!";
  }
}

typedef enum {
  PACKET_OTHER,
  PACKET_UDP,
  PACKET_XPASS,
  PACKET_TCP,
  PACKET_TCP_XPASS,
} packet_type_t;

inline packet_type_t ParseHeader(const bess::Packet *pkt, Ethernet *&eth, Ipv4 *&iph, Tcp *& tcph, Udp *& udph, Xpass *&xph) {
  eth = nullptr;
  iph = nullptr;
  tcph = nullptr;
  udph = nullptr;
  xph = nullptr;

  eth = pkt->head_data<Ethernet *>();
  if (eth->ether_type != be16_t(Ethernet::Type::kIpv4))
    return PACKET_OTHER;
    
  iph = reinterpret_cast<Ipv4 *>(eth + 1);
  int dscp = iph->type_of_service >> 2;
  uint8_t ip_hdrlen = (iph->header_length) << 2;

  if (iph->protocol == Ipv4::Proto::kUdp) {
    udph =  reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(iph) + ip_hdrlen);
    if (dscp != bess::utils::GDX_DSCP_EXPPASS && dscp != bess::utils::GDX_DSCP_PROACTIVE 
      && dscp != bess::utils::GDX_DSCP_REACTIVE && dscp != bess::utils::GDX_DSCP_CREDIT) {
      return PACKET_UDP;
    }
    xph = reinterpret_cast<Xpass *>(reinterpret_cast<uint8_t *>(udph) + sizeof(Udp));
    return PACKET_XPASS;
  } else if (iph->protocol == Ipv4::Proto::kTcp) {
    tcph = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(iph) + ip_hdrlen);
    if (dscp != bess::utils::GDX_DSCP_EXPPASS && dscp != bess::utils::GDX_DSCP_PROACTIVE 
      && dscp != bess::utils::GDX_DSCP_REACTIVE && dscp != bess::utils::GDX_DSCP_CREDIT) {
      return PACKET_TCP;
    }
    if ((tcph->offset << 2) < 20) {
      return PACKET_TCP;
    }
    XpassTcpOption *xopt = reinterpret_cast<XpassTcpOption *>(reinterpret_cast<uint8_t *>(tcph) + ((tcph->offset) << 2) - sizeof(XpassTcpOption));
    if (xopt->tcp_option_type != bess::utils::XPASS_TCP_OPTION_TYPE || xopt->tcp_option_len != sizeof(XpassTcpOption)) {
      xph = nullptr;
      return PACKET_TCP;
    }
    xph = &xopt->xpass;
    return PACKET_TCP_XPASS;
  } else {
    return PACKET_OTHER;
  }
}

// RX Path implementations
void XPassCore::ReceiveRx(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::XpassTcpOption;

  bess::PacketBatch *new_batch = ctx->task->AllocPacketBatch();
  int cnt = batch->cnt();

  for (int i=0; i<cnt; i++) {
    Ethernet *eth;
    Ipv4 *iph = nullptr;
    Tcp *tcph;
    Xpass xph;
    XpassTcpOption *xopt;
    uint8_t ip_hdrlen = 0, *payload;
    uint16_t ip_payload_len, tcp_hdrlen, tcp_payload_len;
    NetworkFlow *flow = nullptr;
    uint8_t dscp;
    bool xph_valid = false;

    bess::Packet *pkt = batch->pkts()[i];

    if((int)(pkt->total_len()) < (int)(sizeof(Ethernet) + sizeof(Ipv4))) {
      goto bypass;
    }

    eth = pkt->head_data<Ethernet *>();
    if (eth->ether_type != be16_t(Ethernet::Type::kIpv4))
      goto bypass;
      
    iph = reinterpret_cast<Ipv4 *>(eth + 1);
    ip_hdrlen = (iph->header_length) << 2;
    ip_payload_len = iph->length.value() - ip_hdrlen;
      
    dscp = iph->type_of_service >> 2;
    if (dscp != bess::utils::GDX_DSCP_EXPPASS && dscp != bess::utils::GDX_DSCP_PROACTIVE && dscp != bess::utils::GDX_DSCP_REACTIVE && dscp != bess::utils::GDX_DSCP_CREDIT) {
      if (iph->protocol == Ipv4::Proto::kTcp) {
        tcph = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(iph) + ip_hdrlen);
        if ((tcph->flags & Tcp::Flag::kSyn) || (tcph->flags & Tcp::Flag::kFin)) {
          goto bypass_xpass_remove;
        }
      }
      goto bypass;
    }
    
    if (iph->protocol == Ipv4::Proto::kUdp)
      goto process_xpass;
    if (iph->protocol != Ipv4::Proto::kTcp)
      goto bypass;


    tcph = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(iph) + ip_hdrlen);

    tcp_hdrlen = (tcph->offset) << 2;
    tcp_payload_len = ip_payload_len - tcp_hdrlen;
    payload = reinterpret_cast<uint8_t *>(
        reinterpret_cast<uint8_t *>(tcph) + tcp_hdrlen);
    if (tcp_hdrlen < 20 + sizeof(XpassTcpOption))
      goto bypass_xpass_remove;

    xopt = reinterpret_cast<XpassTcpOption *>(payload - sizeof(XpassTcpOption));
    if (xopt->tcp_option_type != bess::utils::XPASS_TCP_OPTION_TYPE || xopt->tcp_option_len != sizeof(XpassTcpOption))
      goto bypass_xpass_remove;

    xph_valid = true;
    // copy xpass header
    bess::utils::Copy(&xph, &xopt->xpass, sizeof(Xpass));
    if (tcp_payload_len) {
      // shift header backward
      uint8_t *prev_head = pkt->head_data<uint8_t *>();
      memmove(pkt->adj(sizeof(XpassTcpOption)), prev_head, payload - prev_head - sizeof(XpassTcpOption));

      //recalculate header pos
      eth = reinterpret_cast<Ethernet *> (reinterpret_cast<uint8_t *>(eth) + sizeof(XpassTcpOption));
      iph = reinterpret_cast<Ipv4 *> (reinterpret_cast<uint8_t *>(iph) + sizeof(XpassTcpOption));
      tcph = reinterpret_cast<Tcp *> (reinterpret_cast<uint8_t *>(tcph) + sizeof(XpassTcpOption));
    } else {
      pkt->trim(sizeof(XpassTcpOption));
    }

    tcph->offset = (tcp_hdrlen - sizeof(XpassTcpOption)) >> 2;
    iph->length = be16_t(iph->length.value() - sizeof(XpassTcpOption));

#if !SKIP_RX_CHECKSUM
    iph->checksum = CalculateIpv4Checksum(*iph);
    tcph->checksum = CalculateIpv4TcpChecksum(*iph, *tcph); 
#endif

    // fallthrough
bypass_xpass_remove:

    flow = FindReverseFlow(iph, tcph);
    if (!flow) {
      NetworkFlowKey new_key;
      new_key.setReverse(iph, tcph);

      LOG(INFO) << "Inserting new flow!";
      flow = AllocateFlow(new_key, ctx);
      flow->generateCreditTemplate(eth, iph, tcph, true);
    }

    flow->tmr_credit_response_timeout_ = now() + CREDIT_RESPONSE_TIMEOUT;

#if TCP_DEBUG
    if (!xph_valid) {
      LOG(INFO) << "Received ack? DSCP=" << (int)dscp
                << ", ack=" << tcph->ack_num.value()
                << ", seq=" << tcph->seq_num.value();
    } else {
      LOG(INFO) << "Received data DSCP=" << (int)dscp
                << ", seq=" << tcph->seq_num.value()
                << ", ack=" << tcph->ack_num.value()
                << ", len=" << tcp_payload_len;
    }
#else
    (void)xph_valid;
#endif
    ReceiveDataRx(flow, eth, iph, tcph, xph_valid ? (&xph) : nullptr);
    // should not access flow from here
    // fallthrough
bypass:
    new_batch->add(pkt);
    
    if (pkt->total_len() > (int)(9014 - sizeof(XpassTcpOption))) {
      LOG(INFO) << "Total Len is " << pkt->total_len();
      // assert(0);
    }

    if(new_batch->full()) {
      LOG(INFO) << "Batch full, " << cnt << " packets in batch";
      RunChooseModule(ctx, OGATE_TO_KERNEL, new_batch);
      new_batch = ctx->task->AllocPacketBatch();
      new_batch->clear();
    }
    continue;

process_xpass:
    if (iph && ip_hdrlen) {
      Udp *udph =  reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(iph) + ip_hdrlen);
      Xpass *xph = reinterpret_cast<Xpass *>(udph+1);

      if (!flow)
        flow = FindReverseFlow(iph, udph);
      if (flow)
        ReceiveXpassRx(flow, xph);
      // else
      //   LOG(INFO) << "Cannot find flow for UDP";
    }
    bess::Packet::Free(pkt);
}
  RunChooseModule(ctx, OGATE_TO_KERNEL, new_batch);
}

bool XPassCore::ReceiveDataRx(NetworkFlow *flow, Ethernet *eth, Ipv4 *iph, Tcp *tcph, Xpass *xph) {
  
  if (xph && xph->credit_seq.value()) {
    uint32_t distance = xph->credit_seq.value() - flow->c_recv_next_;
    if (xph->credit_seq.value() < flow->c_recv_next_) {
      // credit packet reordering or credit sequence number overflow happened.
      LOG(ERROR) << "ERROR: Credit Sequence number is reverted. Expected > " << std::ios::hex << flow->c_recv_next_  << 
      ", got " <<  xph->credit_seq.value() << std::ios::dec;
    } else {
      flow->credit_total_ += (distance + 1);
      flow->credit_dropped_ += distance;
    }
    flow->c_recv_next_ = xph->credit_seq.value() + 1;
  }
  
  if ((tcph->flags & Tcp::Flag::kSyn) && !(tcph->flags & Tcp::Flag::kAck)) {
    ReceiveSynRx(flow, eth, iph, tcph);
    if (!xph) {
      flow->bypass_ = true;
    }
  } else if ((tcph->flags & Tcp::Flag::kSyn) && (tcph->flags & Tcp::Flag::kAck)) {
    ReceiveSynAckRx(flow);
    if (!xph) {
      flow->bypass_ = true;
    }
  } else if ((tcph->flags & Tcp::Flag::kFin)) {
    
    // LOG(INFO) << "Detect FIN Rx! state=" << flow->tcp_state_;
    if (flow->tcp_state_ == XPASS_TCP_ESTABLISHED) {
      flow->SetTCPState(XPASS_TCP_CLOSE_WAIT);
    } else if (flow->tcp_state_ == XPASS_TCP_FIN_WAIT) {
      flow->SetTCPState(XPASS_TCP_CLOSED);
      LOG(INFO) << "Client-side TCP close complete!";
    }
  } else if ((tcph->flags & Tcp::Flag::kRst)) {
    flow->SetTCPState(XPASS_TCP_CLOSED);
  } else if ((tcph->flags & Tcp::Flag::kAck)) {
    ReceiveAckRx(flow);
  }

  if (xph && xph->credit_seq.value()) {
    // update RTT
    uint64_t rtt = flow->elapsed() - static_cast<uint64_t>(xph->credit_sent_time.value()) * 10;
    rtt = rtt % UINT32_MAX;
    if (flow->rtt_ > 0) {
      flow->rtt_ = (3*flow->rtt_ + rtt) / 4;
    } else {
      flow->rtt_ = rtt;
    }
    // LOG(INFO) << "RTT is " << flow->rtt_/1000000. << "ms";
  }

  if (flow->tcp_state_ == XPASS_TCP_CLOSED) {
    LOG(INFO) << "TCP closed, destroying flow";
    if (flow->credit_recv_state_ == XPASS_RECV_CREDIT_RECEIVING) {
      SendSingle(flow, CreateCreditStop(flow));
    }
    EvictFlow(flow);
    return false;
  }
  return true;
}

void XPassCore::CreditFeedbackControl(NetworkFlow *flow) {
  if (flow->rtt_ <= 0) {
    return;
  }
  if ((flow->elapsed() - flow->last_credit_rate_update_) < flow->rtt_) {
    return;
  }
  if (flow->credit_total_ == 0) {
    return;
  }

  uint32_t old_rate = flow->cur_credit_rate_;
  double loss_rate = flow->credit_dropped_/(double)flow->credit_total_;
  uint32_t min_rate = (int)(flow->credit_template_size_ * 1000000000ULL / flow->rtt_);

  // Original
  double target_loss = (1.0 - flow->cur_credit_rate_/(double)flow->max_credit_rate_) * flow->target_loss_scaling_;

  if (loss_rate > target_loss) {
    // congestion has been detected!
   if (loss_rate >= 1.0) {
      flow->cur_credit_rate_ = (int)(flow->credit_template_size_ * 1000000000ULL / flow->rtt_);
    } else {
      flow->cur_credit_rate_ = (int)(flow->credit_template_size_*(flow->credit_total_ - flow->credit_dropped_) * 1000000000ULL
                         / (flow->elapsed() - flow->last_credit_rate_update_)
                         * (1.0+target_loss));
    }
    if (flow->cur_credit_rate_ > old_rate) {
      flow->cur_credit_rate_ = old_rate;
    }

    flow->w_ = MAX(flow->w_/2.0, flow->min_w_);
    flow->can_increase_w_ = false;
    // printf("[CFC] CGST CCR=%10d => %10d, LR=%10lf, TLR=%10lf\n", old_rate, cur_credit_rate_, loss_rate, target_loss);
  } else {
    // there is no congestion.
    if (flow->can_increase_w_) {
      flow->w_ = MIN(flow->w_ + 0.05, 0.5);
    }else {
      flow->can_increase_w_ = true;
    }

    if (flow->cur_credit_rate_ < flow->max_credit_rate_) {
      flow->cur_credit_rate_ = (int)(flow->w_*flow->max_credit_rate_ + (1-flow->w_)*flow->cur_credit_rate_);
    }
    //printf("[CFC] ---- CCR=%10d => %10d, LR=%10lf, TLR=%10lf\n", old_rate, cur_credit_rate_, loss_rate, target_loss);
  }

  if (flow->cur_credit_rate_ > flow->max_credit_rate_) {
    flow->cur_credit_rate_ = flow->max_credit_rate_;
  }
  if (flow->cur_credit_rate_ < min_rate) {
    flow->cur_credit_rate_ = min_rate;
  }
  
  flow->credit_total_ = 0;
  flow->credit_dropped_ = 0;
  flow->last_credit_rate_update_ = flow->elapsed();
  // LOG(INFO) << "Credit sending rate updated " << old_rate << " -> " << flow->cur_credit_rate_;

  flow->credit_token_bucket_.setRefreshTime(flow->getCreditPeriod());
}

// bool integrityCheck(bess::Packet *pkt) {
//   Ethernet *eth; Ipv4 *iph; Tcp *tcph; Udp *udph; Xpass *xph_;
//   auto parse = ParseHeader(pkt, eth, iph, tcph, udph, xph_);
//   if (parse == PACKET_TCP_XPASS || parse == PACKET_TCP) {
//     if ((tcph->offset << 2) < 20) {
//       return false;
//     }
//   }
//   return true;
// }

void XPassCore::ReceiveXpassRx(NetworkFlow *flow, Xpass *xph) {
  if (xph->packet_type == Xpass::kCredit) {
    // data sender
    // LOG(INFO) << "Received Credit #" << xph->credit_seq.value() << ", queue len = " << flow->queue_->cnt();
    if (flow->credit_recv_state_ == XPASS_RECV_CREDIT_REQUEST_SENT)
      flow->credit_recv_state_ = XPASS_RECV_CREDIT_RECEIVING;
      
    assert(flow->queue_);
    bool flow_available = true;
    if (!flow->queue_->empty()) {
      flow->tmr_credit_stop_send_timeout_ = now() + CREDIT_STOP_SEND_TIMEOUT;

      // int intg = flow->queue_->checkIntegrity(integrityCheck);
      // if (intg >= 0) {
      //   PrintArray(flow->queue_->pkts()[intg]->head_data(), flow->queue_->pkts()[intg]->total_len());
      // }

      bess::Packet *pkt = flow->queue_->peek_front();
      flow->queue_->pop_front();
      assert(pkt);

      Ethernet *eth; Ipv4 *iph; Tcp *tcph; Udp *udph; Xpass *xph_;
      auto parse = ParseHeader(pkt, eth, iph, tcph, udph, xph_);
      if (parse == PACKET_TCP || parse == PACKET_TCP_XPASS) {
        flow_available = ReceiveDataTx(flow, eth, iph, tcph);
      }
      if (parse == PACKET_TCP_XPASS) {
        // LOG(INFO) << "Sending back information: Credit seq = "
        //           << xph->credit_seq.value();
        xph_->credit_seq = xph->credit_seq;
        xph_->credit_sent_time = xph->credit_sent_time;
        xph_->orig_seqno = xph->orig_seqno;
        xph_->packet_type = Xpass::kData;
      }
      if (parse == PACKET_TCP_XPASS || parse == PACKET_TCP) {
        DoTcpChecksum(pkt, iph, tcph);
      }
      if (pkt->total_len() > (int)(9014)) {
        LOG(INFO) << "Total Len is " << pkt->total_len();
        // assert(0);
      }

      SendSingle(flow, pkt);
    }
    if (flow_available && flow->queue_->empty() && flow->credit_recv_state_ == XPASS_RECV_CREDIT_RECEIVING) {
      if (flow->tmr_credit_stop_send_timeout_ < now()) {
        LOG(INFO) << "Sending Credit Stop since buffer was empty for timeout";
        flow->tmr_credit_stop_send_timeout_ = 0;
        flow->credit_recv_state_ = XPASS_RECV_CREDIT_STOP_SENT;
        SendSingle(flow, CreateCreditStop(flow));
      }
    }
  } else if (xph->packet_type == Xpass::kCreditStopAck) {
    // data sender 
    LOG(INFO) << "Received Credit stop ack. Successfully stopped.";
    flow->tmr_credit_stop_send_timeout_ = 0;
    flow->credit_recv_state_ = XPASS_RECV_CLOSED;
  } else if (xph->packet_type == Xpass::kCreditRequest) {
    // data receiver 
    LOG(INFO) << "Received Credit request. Sending credit";
    if (flow->credit_send_state_ == XPASS_SEND_CLOSED || flow->credit_send_state_ == XPASS_SEND_CREDIT_STOP_RECEIVED) {
      flow->Init(true);
      flow->credit_send_state_ = XPASS_SEND_CREDIT_SENDING;
    }
    SendSingle(flow, CreateCredit(flow));
    flow->tmr_credit_response_timeout_ = now() + CREDIT_RESPONSE_TIMEOUT;
  } else if (xph->packet_type == Xpass::kCreditStop) {
    // data receiver 
    LOG(INFO) << "Received Credit stop. Sending credit stop ack";
    flow->credit_send_state_ = XPASS_SEND_CLOSED;
    SendSingle(flow, CreateCreditStopAck(flow));
  }
}
void XPassCore::ReceiveCreditRx() {

}

void XPassCore::ReceiveSynRx(NetworkFlow *flow, Ethernet *, Ipv4 *, Tcp *) {
  // Got Syn from RX path
  // Init flow.
  flow->Init();

  // 3. change TCP state
  flow->SetTCPState(XPASS_TCP_SYN_RECEIVED);
    LOG(INFO) << "Received SYN";
}

void XPassCore::ReceiveSynAckRx(NetworkFlow *flow) {
  if (flow->tcp_state_ == XPASS_TCP_SYN_SENT) {
    flow->SetTCPState(XPASS_TCP_SYNACK_RECEIVED);
    LOG(INFO) << "Received SYNACK, Connection Established!";
  }

  if (flow->credit_recv_state_ == XPASS_RECV_CLOSED && flow->queue_->cnt() > 0) {
    LOG(INFO) << "Sending Credit Request!";
    flow->credit_recv_state_ = XPASS_RECV_CREDIT_REQUEST_SENT;
    flow->tmr_credit_request_timeout_ = now() + CREDIT_REQUEST_TIMEOUT;
    SendSingle(flow, CreateCreditRequest(flow));
  }
}

void XPassCore::ReceiveAckRx(NetworkFlow *flow) {
  if(flow->tcp_state_ == XPASS_TCP_SYNACK_SENT) {
    flow->SetTCPState(XPASS_TCP_ESTABLISHED);
    LOG(INFO) << "Connection Established!";
  } else if (flow->tcp_state_ == XPASS_TCP_LAST_ACK) {
    flow->SetTCPState(XPASS_TCP_CLOSED);
    LOG(INFO) << "Passive TCP close complete!";
  }
}
uint32_t XPassCore::ProcessFlowTask(NetworkFlow *flow, Context *ctx, bess::PacketBatch *&batch, size_t *p_pkt_size) {
  uint32_t pkt_cnt = 0;
  size_t pkt_size = 0;

  if (flow->credit_recv_state_ == XPASS_RECV_CREDIT_REQUEST_SENT && flow->tmr_credit_request_timeout_ < now()) {
    batch->add(CreateCreditRequest(flow));
    if(batch->full()) {
      RunChooseModule(ctx, OGATE_TO_NIC, batch);
      batch = ctx->task->AllocPacketBatch();
      batch->clear();
    }
    pkt_cnt ++;
    pkt_size += flow->credit_template_size_;
    flow->tmr_credit_request_timeout_ = now() + CREDIT_REQUEST_TIMEOUT;
  }

  // credit stop timer
  if (flow->credit_send_state_ == XPASS_SEND_CREDIT_SENDING && flow->tmr_credit_response_timeout_ < now()) {
    flow->credit_send_state_ = XPASS_SEND_CLOSED;
    batch->add(CreateCreditStopAck(flow));
    if(batch->full()) {
      RunChooseModule(ctx, OGATE_TO_NIC, batch);
      batch = ctx->task->AllocPacketBatch();
      batch->clear();
    }
    pkt_cnt ++;
    pkt_size += flow->credit_template_size_;
  }

  if (flow->credit_send_state_ == XPASS_SEND_CREDIT_SENDING) {
    CreditFeedbackControl(flow);
    flow->credit_token_bucket_.updateToken(now());
    uint32_t token = flow->credit_token_bucket_.getToken() / flow->credit_template_size_;
    while (token--) {
      bess::Packet *credit = CreateCredit(flow);
      if (credit) {
        pkt_cnt ++;
        pkt_size += flow->credit_template_size_;
        batch->add(credit);
        if(batch->full()) {
          RunChooseModule(ctx, OGATE_TO_NIC, batch);
          batch = ctx->task->AllocPacketBatch();
          batch->clear();
        }
      }
      flow->credit_token_bucket_.consumeToken(flow->credit_template_size_);
    }
  }

  *p_pkt_size += pkt_size;
  return pkt_cnt;
}

// https://lemire.me/blog/2018/03/08/iterating-over-set-bits-quickly-simd-edition/
struct task_result XPassCore::RunTask(Context *ctx, bess::PacketBatch *batch, void *) {
  (void)ctx;
  
  uint32_t pkt_cnt = 0;
  size_t pkt_size = 0;

#if OPTIMIZE_FLOW_ALLOC
  if (flow_count == 0) {
    return {.block = true, .packets = 0, .bits = 0};
  }

  batch->clear();
  for (size_t k = 0; k < MAX_NUM_FLOW / 64; ++k) {
    uint64_t bitset = flow_bitmap[k];
    while (bitset != 0) {
      uint64_t t = bitset & -bitset;
      int r = __builtin_ctzll(bitset);
      NetworkFlow *flow = &flow_slot[k * 64 + r];
      pkt_cnt += ProcessFlowTask(flow, ctx, batch, &pkt_size);
      bitset ^= t;
    }
  }
#else
  batch->clear();
  for (auto it = flow_table.begin(); it != flow_table.end(); ++it) {
    pkt_cnt += ProcessFlowTask(it->second, ctx, batch, &pkt_size);
  }
#endif

  if (pkt_cnt) {
    RunChooseModule(ctx, OGATE_TO_NIC, batch);
  }
  return {.block = (pkt_cnt == 0), .packets = pkt_cnt, .bits = pkt_size};
}

bess::Packet* XPassCore::CreateControlPacket(NetworkFlow *flow, bess::utils::Xpass::XPassPacketType type) {
  using bess::utils::Udp;
  bess::Packet *pkt = current_worker.packet_pool()->Alloc(flow->credit_template_size_);
  if (!pkt) {
    LOG(ERROR) << "Packet ALLOC Fail";
    return nullptr;
  }
  bess::utils::Copy(pkt->head_data(), flow->credit_template_,
                    flow->credit_template_size_);
  Ipv4 *iph =
      reinterpret_cast<Ipv4 *>(reinterpret_cast<uint8_t *>(pkt->head_data()) +
                                sizeof(Ethernet));
  Udp *udph =
      reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(pkt->head_data()) +
                                sizeof(Ethernet) + sizeof(Ipv4));
  Xpass *xph =
      reinterpret_cast<Xpass *>(reinterpret_cast<uint8_t *>(pkt->head_data()) +
                                sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Udp));

                                
  xph->packet_type = type;
  if (type == Xpass::kCredit) {
    iph->type_of_service = (iph->type_of_service & 0x3) | (bess::utils::GDX_DSCP_CREDIT << 2);
    xph->credit_seq = be32_t(flow->credit_seq_++);
    uint32_t target_elapsed = static_cast<uint32_t>(flow->elapsed() / 10);
    xph->credit_sent_time = be32_t(target_elapsed == 0 ? 1 : target_elapsed); // make elapsed != 0
  } else {
    iph->type_of_service = (iph->type_of_service & 0x3) | (bess::utils::GDX_DSCP_EXPPASS << 2);
  }

  DoUdpChecksum(pkt, iph, udph);

  return pkt;
}

void NetworkFlow::generateCreditTemplate(Ethernet *eth, Ipv4* iph, Tcp *tcph, bool reverse) {
  using bess::utils::Udp;

  unsigned char *ptr = this->credit_template_;
  if (reverse) {
    Ethernet eth_rev = {eth->src_addr, eth->dst_addr,
                    eth->ether_type};
    bess::utils::Copy(ptr, &eth_rev, sizeof(Ethernet));
  } else {
    bess::utils::Copy(ptr, eth, sizeof(Ethernet));
  }

  ptr += sizeof(Ethernet);
  assert(sizeof(Ipv4) == (iph->header_length << 2));
  bess::utils::Copy(ptr, iph, sizeof(Ipv4));
  Ipv4 *iph_copy = reinterpret_cast<Ipv4 *>(ptr);
  iph_copy->length = be16_t(sizeof(Ipv4) + sizeof(Udp) + sizeof(Xpass));
  iph_copy->protocol = Ipv4::kUdp;
  iph_copy->type_of_service =
      (iph_copy->type_of_service & 0x3) | (bess::utils::GDX_DSCP_CREDIT << 2);
  if (reverse) {
    iph_copy->dst = iph->src;
    iph_copy->src = iph->dst;
  }
  ptr += (iph_copy->header_length) << 2;

  Udp udp = {
    reverse ? tcph->dst_port : tcph->src_port,
    reverse ? tcph->src_port : tcph->dst_port,
    be16_t(sizeof(Udp) + sizeof(Xpass)), 
    0
  };

  bess::utils::Copy(ptr, &udp, sizeof(Udp));
  // Udp *udp_copy = reinterpret_cast<Udp *>(ptr);
  // udp_copy->src_port = tcph->src_port;
  // udp_copy->length = be16_t(sizeof(Udp) + sizeof(Xpass));
  ptr += sizeof(Udp);

  Xpass xpass;
  memset(&xpass, 0, sizeof(Xpass));
  xpass.packet_type = Xpass::kCredit;
  bess::utils::Copy(ptr, &xpass, sizeof(Xpass));


  credit_template_size_ = MAX(ptr - this->credit_template_, 46 + sizeof(Ethernet));
  LOG(INFO) << "Credit template size: " << credit_template_size_;

  assert(ptr < this->credit_template_ + kMaxCreditTemplateSize);
}

NetworkFlow *XPassCore::AllocateFlow(const NetworkFlowKey &key, Context *ctx) {
  
#if OPTIMIZE_FLOW_ALLOC
  // find empty slots
  int pos = -1;
  for (int i = 0; i < MAX_NUM_FLOW / 64; i++) {
    uint64_t empty_slots = ~flow_bitmap[i];
    if (empty_slots) {
      pos = (i << 6) + __builtin_ctzll(empty_slots);
      break;
    }
  }

  if (unlikely(pos < 0)) {
    LOG(ERROR) << "Cannot allocate flow!";
    return nullptr;
  }

  NetworkFlow *flow = &flow_slot[pos];
  flow_bitmap[pos / 64] |= ((1LLU << (pos % 64)) & UINT64_MAX);
  LOG(INFO) << "ALLOC Flow bitmap[" << (pos / 64) << "] = " << std::hex << flow_bitmap[pos / 64] << std::dec ;
  flow_count++;
#else
  NetworkFlow *flow = new NetworkFlow();
#endif
  flow->Init(key, ctx);
  flow_table.insert(std::pair<NetworkFlowKey, NetworkFlow *>(key, flow));
  return flow;
}

void XPassCore::EvictFlow(NetworkFlow *flow) {
  flow->Free();
  flow_table.erase(flow->network_flow_key_);
#if OPTIMIZE_FLOW_ALLOC
  int pos = flow - flow_slot;
  flow_bitmap[pos / 64] &= ~((1LLU << (pos % 64)) & UINT64_MAX);
  assert(flow_count);
  flow_count--;
  LOG(INFO) << "EVICT Flow bitmap[" << (pos / 64) << "] = " << std::hex
            << flow_bitmap[pos / 64] << std::dec;
#else
  delete flow;
#endif
}

ADD_MODULE(XPassCore, "xpass-core", "ExpressPass core module")
