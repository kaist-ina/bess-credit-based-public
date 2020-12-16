#ifndef BESS_MODULE_XPASS_H_
#define BESS_MODULE_XPASS_H_

#include "../module.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/xpass.h"
#include "../utils/time.h"
#include "../utils/checksum.h"
#include "../utils/circular_queue.h"
#include "../pb/module_msg.pb.h"

#include <map>

#define IGATE_FROM_TX 0
#define IGATE_FROM_RX 1
#define IGATE_MAX 2

#define OGATE_TO_KERNEL 0
#define OGATE_TO_NIC 1
#define OGATE_MAX 2

#define CREDIT_SIZE 14+20+20+12
#define XPASS_IP_PROTO 146

#define MAX_NUM_FLOW 512

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Xpass;
using bess::utils::Tcp;
using bess::utils::Udp;
using bess::utils::Vlan;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::XpassTcpOption;

typedef enum XPASS_TCP_STATE_ {
  XPASS_TCP_CLOSED,
  XPASS_TCP_SYN_SENT,
  XPASS_TCP_SYN_RECEIVED,
  XPASS_TCP_SYNACK_SENT,
  XPASS_TCP_SYNACK_RECEIVED,
  XPASS_TCP_ESTABLISHED,
  XPASS_TCP_FIN_WAIT,
  XPASS_TCP_CLOSE_WAIT,
  XPASS_TCP_LAST_ACK,
} XPASS_TCP_STATE;

const char * XPASS_TCP_STATE_NAME[] = {
  "XPASS_TCP_CLOSED", 
  "XPASS_TCP_SYN_SENT", 
  "XPASS_TCP_SYN_RECEIVED", 
  "XPASS_TCP_SYNACK_SENT", 
  "XPASS_TCP_SYNACK_RECEIVED", 
  "XPASS_TCP_ESTABLISHED", 
  "XPASS_TCP_FIN_WAIT", 
  "XPASS_TCP_CLOSE_WAIT", 
  "XPASS_TCP_LAST_ACK", 
};
typedef enum XPASS_SEND_STATE_ {
  XPASS_SEND_CLOSED,
  XPASS_SEND_CREDIT_SENDING,
  XPASS_SEND_CREDIT_STOP_RECEIVED,
  XPASS_SEND_NSTATE,
} XPASS_SEND_STATE;

typedef enum XPASS_RECV_STATE_ {
  XPASS_RECV_CLOSED,
  XPASS_RECV_CREDIT_REQUEST_SENT,
  XPASS_RECV_CREDIT_RECEIVING,
  XPASS_RECV_CREDIT_STOP_SENT,
  XPASS_RECV_NSTATE,
} XPASS_RECV_STATE;

struct list_elem {
  struct list_elem* prev;
  struct list_elem* next;
};

// Currently only support TCP.
typedef struct network_flow_key_ {
public:
  be32_t src_ip;
  be32_t dst_ip;
  be16_t src_port;
  be16_t dst_port;

  inline bool operator==(const network_flow_key_ &other) const {
    return (src_ip == other.src_ip) &&
           (dst_ip == other.dst_ip) &&
	   (src_port == other.src_port) &&
	   (dst_port == other.dst_port);
  }

  inline bool operator<(const network_flow_key_& other) const {
    return (src_ip < other.src_ip) ||
           (dst_ip < other.dst_ip) ||
	   (src_port < other.src_port) ||
	   (dst_port < other.dst_port);
  }

  inline std::ostream& operator<<(std::ostream& os) {
    os << bess::utils::ToIpv4Address(src_ip)
       << ":" << src_port.value()
       << " -> "
       << bess::utils::ToIpv4Address(dst_ip)
       << ":" << dst_port.value();
    return os;
  }

  inline void setForward(Ipv4 *iph, Tcp *tcph) {
    src_ip = iph->src;
    dst_ip = iph->dst;
    src_port = tcph->src_port;
    dst_port = tcph->dst_port;
  }

  inline void setReverse(Ipv4 *iph, Tcp *tcph) {
    src_ip = iph->dst;
    dst_ip = iph->src;
    src_port = tcph->dst_port;
    dst_port = tcph->src_port;
  }
} NetworkFlowKey;


class TokenBucket {
public:
  void Init(uint32_t rtime, uint64_t now) {
    token_ = 0;
    last_updated_time_ = now;
    refresh_time_ = rtime;
  }

  inline void updateToken(uint64_t now) {
    if (now <= last_updated_time_) {
      return;
    }
    if (unlikely(!refresh_time_)) {
      return;
    }

    uint32_t new_tokens = (now - last_updated_time_)/refresh_time_;
    if (new_tokens > 0) {
      token_ = std::min<uint32_t>(kMaxBurst, token_ + new_tokens);
      last_updated_time_ += new_tokens*refresh_time_;
    }
  }

  inline uint32_t getToken() {
    return token_;
  }

  inline void consumeToken(uint32_t token_used) {
    assert(token_used <= token_);
    token_ -= token_used;
  }

  inline void setRefreshTime(uint32_t ref) { refresh_time_ = ref; }
  static const uint32_t kMaxBurst = CREDIT_SIZE * 8;
 private:
  uint32_t refresh_time_;
  uint32_t token_; // in bytes
  uint64_t last_updated_time_; // in ns
  // the time to take to fill 1 bytes. (ns per bytes)
  // minimum rate = 1 bytes / 2^32 ns ~ 2bps
  // maximum rate = 1 bytes / 1 ns ~ 8Gbps
};

static_assert(std::is_standard_layout<TokenBucket>::value, "not a standard layout");

typedef struct alignas(64) network_flow_ {
  list_elem list;
  const double min_w_ = 0.01;
  const double target_loss_scaling_ = 0.125;
  const uint32_t max_credit_rate_ = 32916392; //185873606;  // 185873606; // bytes/sec
  const uint32_t init_credit_rate_ = 32916392/2;
  XPASS_SEND_STATE credit_send_state_;
  XPASS_RECV_STATE credit_recv_state_;
  XPASS_TCP_STATE tcp_state_;
  uint32_t cur_credit_rate_;
  double alpha_;
  double w_;
  int can_increase_w_;
  bess::utils::CircularQueue *queue_ {nullptr};
  Context *ctx_;
  int bypass_;
  uint64_t rtt_; //ns
  uint32_t credit_seq_;
  uint64_t ts_start_;
  uint64_t last_credit_rate_update_;
  uint32_t c_recv_next_;
  uint32_t credit_total_ ;
  uint32_t credit_dropped_;
  uint64_t tmr_credit_request_timeout_{0};
  uint64_t tmr_credit_response_timeout_{0};
  uint64_t tmr_credit_stop_send_timeout_{0};

  list_elem tx_link;
  static const size_t kMaxCreditTemplateSize = 100;

  uint16_t credit_template_size_;
  unsigned char credit_template_[kMaxCreditTemplateSize];
  NetworkFlowKey network_flow_key_;
  TokenBucket credit_token_bucket_;

  inline void Init(NetworkFlowKey nfk, Context *ctx) {
    Init();


    credit_template_size_ = 0;
    memset(credit_template_, 0, kMaxCreditTemplateSize);

    network_flow_key_ = nfk;
    ctx_ = ctx;
    if (queue_)
      delete queue_;
    queue_ = new bess::utils::CircularQueue();
    if (!queue_) {
      LOG(INFO) << "queue is null!";
    }
    queue_->clear();
  }

  inline void Free() {
    if (queue_)
      delete queue_;
    queue_ = nullptr;
  }

  inline void Init(bool resume = false) {
    LOG(INFO) << "CC variables init.";
    /** 
     * https://www.quora.com/Why-does-ethernet-have-a-minimum-and-maximum-frame-length
     * 
     * Ethernet preamble + FCS = 8 + 4 = 12 Bytes
     * Ethernet header = 14 Bytes
     * Min. Payload for Ethernet = 46 Bytes
     * 
     * Simulator Configuration:
     * Frame = 1538, Credit Size = 84
     * Takes 84/(84+1538) = 5.17% of link
     * With 40Gbps, this should be 258MB/s
     * 
     * In reality:
     * MTU = 1500, Packet = 1542, Credit Packet Size = 12+14+46 = 72
     * Takes 72/(72+1542) = 4.46% of link
     * With 40Gbps, this should be 223MB/s and 3097893.43 credits/s
     * 3097893.43 credits/s is 185.87 MB/s (credit goodput)
     * 
     * Now using jumbo frame:
     * MTU = 9000, Packet = 9042, Credit Packet Size = 72
     * Takes 72/(72+9042) = 0.790% of link
     * With 40Gbps, this should be 39.5MB/s and 548607 credits/s
     * 548607 credits/s is 32.916392 MB/s
     **/

    if (!resume) {
      credit_send_state_ = XPASS_SEND_CLOSED;
      credit_recv_state_ = XPASS_RECV_CLOSED;
      tcp_state_ = XPASS_TCP_CLOSED;
      cur_credit_rate_ = init_credit_rate_;
      alpha_ = 0.5;
      w_ = 0.0625;
      c_recv_next_ = 1;
      credit_seq_ = 1;
      tx_link.prev = nullptr;
      tx_link.next = nullptr;
      bypass_ = false;
      ts_start_ = now();
      tmr_credit_request_timeout_ = 0;
      tmr_credit_response_timeout_ = 0;
      tmr_credit_stop_send_timeout_ = 0;
    }
    
    // reset every time credit session starts
    
    rtt_ = 0;
    last_credit_rate_update_ = 0;
    can_increase_w_ = false;
    credit_total_ = 0;
    credit_dropped_ = 0;
    credit_token_bucket_.Init(getCreditPeriod(), now());

  }

  inline uint64_t elapsed() {
    return now() - ts_start_;
  }

  inline uint64_t now() {
    return tsc_to_ns(rdtsc());
  }

  inline uint32_t getCreditPeriod() {
    if (likely(cur_credit_rate_))
      return static_cast<uint32_t>(1000000000UL / cur_credit_rate_);  // in nanosecs
    return 0;
  }

  void generateCreditTemplate(Ethernet *eth, Ipv4 *iph, Tcp *tcph, bool reverse = false);

  inline void SetSendState(XPASS_SEND_STATE new_state) {
    credit_send_state_ = new_state;
  }

  inline void SetRecvState(XPASS_RECV_STATE new_state) {
    credit_recv_state_ = new_state;
  }

  inline void SetTCPState(XPASS_TCP_STATE new_state) {
    // LOG(INFO) << "TCP State " << XPASS_TCP_STATE_NAME[tcp_state_] << " -> " << XPASS_TCP_STATE_NAME[new_state];
    tcp_state_ = new_state;
  }

  inline bool IsTxScheduled() {
    return (tx_link.prev || tx_link.next);
  }

} NetworkFlow;

class TimingWheel {
public:
  TimingWheel(): slots_() {}
  static const size_t kNumSlot = 2048;
  static const size_t kGranularity = 4000; // nano seconds.

  inline void Init(uint64_t clock) {
    front_local_ts_ = ConvertToLocalTS(clock);
  }

  inline void ScheduleFlow(NetworkFlow *flow, uint64_t clock) {
    assert(!flow->IsTxScheduled());
    uint64_t now = ConvertToLocalTS(clock);
    size_t idx;
    if (now <= front_local_ts_) {
      idx = currentIdx();
    }else if (now - front_local_ts_ < kNumSlot) {
      idx = now%kNumSlot;
    }else { // beyond the horizon.
      idx = (currentIdx()-1)%kNumSlot;
    }
    assert(idx < kNumSlot);
    if (slots_[idx].next) { // there exist element.
      assert(slots_[idx].prev);
      list_elem *head_elem = &slots_[idx];
      list_elem *last_elem = slots_[idx].prev;

      head_elem->prev = &flow->tx_link;
      last_elem->next = &flow->tx_link;

      flow->tx_link.next = head_elem;
      flow->tx_link.prev = last_elem;
    }else { // this is the first element.
      list_elem *head_elem = &slots_[idx];

      head_elem->prev = &flow->tx_link;
      head_elem->next = &flow->tx_link;

      flow->tx_link.next = head_elem;
      flow->tx_link.prev = head_elem;
    }
  }

  inline void ScheduleFlowNow(NetworkFlow *flow) {
    assert(!flow->IsTxScheduled());
    size_t idx = currentIdx();

    assert (idx < kNumSlot);
    if (slots_[idx].next) {
      assert(slots_[idx].next);
      list_elem *head_elem = &slots_[idx];
      list_elem *last_elem = slots_[idx].prev;

      head_elem->prev = &flow->tx_link;
      last_elem->next = &flow->tx_link;

      flow->tx_link.next = head_elem;
      flow->tx_link.prev = last_elem;
    }else {
      list_elem *head_elem = &slots_[idx];
      assert(!head_elem->prev && !head_elem->next);

      head_elem->prev = &flow->tx_link;
      head_elem->next = &flow->tx_link;

      flow->tx_link.next = head_elem;
      flow->tx_link.prev = head_elem;
    }
  }

  inline void DescheduleFlow(NetworkFlow *flow) {
    list_elem *elem_to_remove = &(flow->tx_link);

    if (!flow->IsTxScheduled()) {
      return;
    }

    assert(flow->IsTxScheduled());

    if (elem_to_remove->next == elem_to_remove->prev) {
      // last element in the list.
      list_elem *head_elem = elem_to_remove->prev;
      assert(head_elem->prev == head_elem->next);

      head_elem->next = nullptr;
      head_elem->prev = nullptr;
      elem_to_remove->next = nullptr;
      elem_to_remove->prev = nullptr;
    }else {
      elem_to_remove->next->prev = elem_to_remove->prev;
      elem_to_remove->prev->next = elem_to_remove->next;

      elem_to_remove->next = nullptr;
      elem_to_remove->prev = nullptr;
    }
  }

  inline void RescheduleFlow(NetworkFlow *flow, uint64_t clock) {
    DescheduleFlow(flow);
    ScheduleFlow(flow, clock);
  }

  inline void RescheduleFlowNow(NetworkFlow *flow) {
    DescheduleFlow(flow);
    ScheduleFlowNow(flow);
  }

  inline NetworkFlow *GetNextFlow(uint64_t clock) {
    uint64_t now = ConvertToLocalTS(clock);
    while (now >= front_local_ts_) {
      if (slots_[currentIdx()].next) { // while slot is not empty
        assert(slots_[currentIdx()].prev);
        list_elem *head_elem = &slots_[currentIdx()];
	list_elem *elem_to_remove = head_elem->next;
	if (head_elem->next == head_elem->prev) { // last element in the list.
	  assert(elem_to_remove->next == elem_to_remove->prev);

	  head_elem->next = nullptr;
	  head_elem->prev = nullptr;
	  elem_to_remove->next = nullptr;
	  elem_to_remove->prev = nullptr;
	}else { // still there are more element in the list.
	  elem_to_remove->next->prev = head_elem;
	  head_elem->next = elem_to_remove->next;

	  elem_to_remove->next = nullptr;
	  elem_to_remove->prev = nullptr;
	}
        return reinterpret_cast<NetworkFlow *>(
	    (char *)elem_to_remove - offsetof(NetworkFlow, tx_link));
      }else {
        assert(!slots_[currentIdx()].prev);
        front_local_ts_++;
      }
    }
    return nullptr;
  }

private:
  struct list_elem slots_[kNumSlot];
  uint64_t front_local_ts_;
  inline size_t currentIdx() {
    return (front_local_ts_%kNumSlot);
  }
  inline uint64_t ConvertToLocalTS(uint64_t wall_clock) {
    return (wall_clock/kGranularity);
  }
};

class XPassCore final : public Module {
public:
  CommandResponse Init(const bess::pb::EmptyArg &);

  static const gate_idx_t kNumIGates = IGATE_MAX;
  static const gate_idx_t kNumOGates = OGATE_MAX;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch);
  
  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch,
                             void *arg) override;

 private:
  // Helper functions
  void SetDSCP(Ipv4 *iph, int dscp);
  NetworkFlow* FindForwardFlow(Ipv4 *iph, Tcp *tcph);
  NetworkFlow* FindReverseFlow(Ipv4 *iph, Tcp *tcph);
  NetworkFlow* FindReverseFlow(Ipv4 *iph, Udp *udph);
  uint64_t now() {
    return tsc_to_ns(rdtsc());
  }

  // TX Path
  void ReceiveTx(Context *ctx, bess::PacketBatch *batch);
  // returns if flow is available
  bool ReceiveDataTx(NetworkFlow *flow, Ethernet *eth, Ipv4 *iph, Tcp *tcph);
  void ReceiveSynTx(NetworkFlow *flow);
  void ReceiveSynAckTx(NetworkFlow *flow);
  void ProcessAckTx(NetworkFlow *flow);

  // RX Path
  void ReceiveRx(Context *ctx, bess::PacketBatch *batch);
  bool ReceiveDataRx(NetworkFlow *flow, Ethernet *eth, Ipv4 *iph, Tcp *tcph, Xpass *xph);
  void ReceiveCreditRx();
  void ReceiveXpassRx(NetworkFlow *flow, Xpass *xph);
  void ReceiveSynRx(NetworkFlow *flow, Ethernet *eth, Ipv4 *iph, Tcp *tcph);
  void ReceiveSynAckRx(NetworkFlow *flow);
  void ReceiveAckRx(NetworkFlow *flow);

  void CreditFeedbackControl(NetworkFlow *flow);

  bess::Packet* CreateControlPacket(NetworkFlow *flow, bess::utils::Xpass::XPassPacketType type);

  inline bess::Packet* CreateCredit(NetworkFlow *flow) {
    return CreateControlPacket(flow, Xpass::kCredit);
  }

  inline bess::Packet* CreateCreditRequest(NetworkFlow *flow) {
    return CreateControlPacket(flow, Xpass::kCreditRequest);
  }
  inline bess::Packet* CreateCreditStop(NetworkFlow *flow) {
    return CreateControlPacket(flow, Xpass::kCreditStop);
  }

  inline bess::Packet* CreateCreditStopAck(NetworkFlow *flow) {
    return CreateControlPacket(flow, Xpass::kCreditStopAck);
  }

  inline void SendSingle(NetworkFlow *flow, bess::Packet *pkt) {
    if (likely(pkt != nullptr)) {
      EmitPacket(flow->ctx_, pkt, OGATE_TO_NIC);
    }
  };

  inline uint32_t ProcessFlowTask(NetworkFlow *flow, Context *ctx, bess::PacketBatch *&batch, size_t *p_pkt_size);


  NetworkFlow *AllocateFlow(const NetworkFlowKey &key, Context *ctx);
  
  void EvictFlow(NetworkFlow *flow);

  TimingWheel tx_timing_wheel;
  inline NetworkFlow *GetFlowList() const { return flow_slot; }

  static void PrintArray(const void *p_, const size_t size) {
    char strbuf[2048] = {
        0,
    };
    char *strp = strbuf;
    const uint8_t *p = reinterpret_cast<const uint8_t *>(p_);
    strp += sprintf(strp, ">> Dump of packet buffer %p (%lu bytes)", p, size);

    for (const uint8_t *ptr = p ; ptr < p + size; ptr++) {
      if ((ptr - p) % 16 == 0)
        strp += sprintf(strp, "\n>> %p <+0x%03lx> : %02x", ptr, ptr - p, *ptr);
      else if ((ptr - p) % 8 == 0)
        strp += sprintf(strp, "  %02x", *ptr);
      else
        strp += sprintf(strp, " %02x", *ptr);
    }
    LOG(INFO) << strbuf;
  }

private:
  NetworkFlow *flow_slot;
  std::map<NetworkFlowKey, NetworkFlow *> flow_table;
  uint64_t flow_bitmap[MAX_NUM_FLOW/64];
  unsigned flow_count;
};
static_assert(MAX_NUM_FLOW % 256 == 0, "MAX_NUM_FLOW must be multiple of 256");

#endif  // BESS_MODULE_XPASS_H_
