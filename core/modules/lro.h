
  
#ifndef BESS_MODULES_LRO_H_
#define BESS_MODULES_LRO_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../xpass_config.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/checksum.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::be16_t;
using bess::utils::be32_t;

struct lro_flow {
  bess::Packet *pkt; /* NULL if empty */
  uint64_t tsc;

  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;

  uint32_t next_seq;  /* in host order */

  /* Offset of (inner, if encapsulated) IP/TCP. */
  uint16_t ip_offset;
  uint16_t tcp_offset;
};

class LRO final : public Module {
public:
  static const gate_idx_t kNumIGates = 1;
  static const gate_idx_t kNumOGates = 1;
  struct lro_flow *worker_flows;
  uint16_t flow_count {0};

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
#if XPASS
  void PopXpass(bess::Packet *pkt, Ipv4 *iph, uint16_t payload_offset);
#endif // XPASS
  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, 
                             void *arg) override;
  CommandResponse Init(const bess::pb::EmptyArg &arg);
  void LroFlushFlow(bess::PacketBatch *batch, struct lro_flow *flow);
  void LroFlushFlow(Context *ctx, struct lro_flow *flow);
  int LroEvictFlow(Context *ctx, struct lro_flow *flows);
  void LroInitFlow(Context *ctx, struct lro_flow *flow, bess::Packet *pkt, 
                   uint16_t ip_offset, uint16_t tcp_offset);
  void LroAppendPkt(Context *ctx, struct lro_flow *flow, bess::Packet *pkt,
                    uint16_t ip_offset, uint16_t tcp_offset);
  void DoLro(Context *ctx, bess::Packet *pkt);
  void EmitPacketAfterConvert(Context *ctx, bess::Packet *src);
};
#endif // BESS_MODULES_LRO_H_