#include "lro.h"
#include "../utils/time.h"

#define MAX_LRO_FLOWS 128

static bess::Packet* convert_to_huge_packet(bess::Packet *src) {
  DCHECK(src->is_linear());

  if (src->pool() == current_worker.huge_packet_pool()->pool()) {
    return src;
  }

  bess::Packet *dst = reinterpret_cast<bess::Packet *>(rte_pktmbuf_alloc(current_worker.huge_packet_pool()->pool()));
  if (unlikely(!dst)) {
    return nullptr;  // FAIL.
  }
  bess::utils::CopyInlined(dst->append(src->total_len()), src->head_data(), src->total_len(), true);
  return dst;
}

void LRO::EmitPacketAfterConvert(Context *ctx, bess::Packet *src) {
  bess::Packet *dst = convert_to_huge_packet(src);
  if (likely(dst != nullptr)) {
    EmitPacket(ctx, dst);
  }
  if (src != dst) {
    bess::Packet::Free(src);
  }
}

CommandResponse LRO::Init(const bess::pb::EmptyArg &){
  worker_flows = new lro_flow[MAX_LRO_FLOWS];
  memset(worker_flows, 0, MAX_LRO_FLOWS * sizeof(lro_flow));
  assert(worker_flows);

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "task creation failed");
  }
  return CommandSuccess();
}

void LRO::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    DoLro(ctx, pkt);
  }
}

struct task_result LRO::RunTask(Context *ctx, bess::PacketBatch *batch,
                                void *) {    
  if (!flow_count) {
    return {
      .block = false,
      .packets = 0,
      .bits = 0};
  }

  uint64_t now = rdtsc();
  uint64_t bytes = 0;
  uint32_t ret = 0;
  uint16_t cnt = flow_count;
  int i;
  batch->clear();

  for (i = 0; i < MAX_LRO_FLOWS; i++) {
    if (likely(!worker_flows[i].pkt))
      continue;

    /* If older than 100us, flush.
     * While 100us seems too much, it is not.
     * (we immediately flush packets if PSH is seen) */
    
    if (tsc_to_us(now - worker_flows[i].tsc) > 100.) {
      bytes += worker_flows[i].pkt->total_len();
      LroFlushFlow(batch, &worker_flows[i]);
      ret++;
    }
    cnt--;
    if (!cnt)
      break;
  }
  if (ret)
    RunNextModule(ctx, batch);

  return {
      .block = false,
      .packets = ret,
      .bits = bytes * 8};
}

void LRO::LroFlushFlow(bess::PacketBatch *batch, struct lro_flow *flow) {
  if (unlikely(flow==nullptr))
    return;

  /* No checksum calculation here (Use checksum modules).  No VXLAN Support */
  Ipv4 *iph = flow->pkt->head_data<Ipv4 *>(flow->ip_offset);
  Tcp *tcph = flow->pkt->head_data<Tcp *>(flow->tcp_offset);

  iph->checksum = CalculateIpv4Checksum(*iph);
  tcph->checksum = CalculateIpv4TcpChecksum(*iph, *tcph);

  batch->add(flow->pkt);
  flow->pkt = NULL;
  assert(flow_count);
  flow_count--;
}

void LRO::LroFlushFlow(Context *ctx, struct lro_flow *flow) {
  if (unlikely(flow==nullptr))
    return;

  /* No checksum calculation here (Use checksum modules).  No VXLAN Support */
  Ipv4 *iph = flow->pkt->head_data<Ipv4 *>(flow->ip_offset);
  Tcp *tcph = flow->pkt->head_data<Tcp *>(flow->tcp_offset);

  iph->checksum = CalculateIpv4Checksum(*iph);
  tcph->checksum = CalculateIpv4TcpChecksum(*iph, *tcph);

  EmitPacket(ctx, flow->pkt);
  flow->pkt = NULL;
  assert(flow_count);
  flow_count--;
}

int LRO::LroEvictFlow(Context *ctx, struct lro_flow *flows) {
  int oldest = 0;
  int i;

  /* We assume no slots are empty */
  for (i = 1; i < MAX_LRO_FLOWS; i++) {
    if (flows[oldest].tsc > flows[i].tsc)
      oldest = i;
  }

  LroFlushFlow(ctx, &flows[oldest]);
  return oldest;
}

void LRO::LroInitFlow(Context *ctx, struct lro_flow *flow, bess::Packet *pkt, uint16_t ip_offset, uint16_t tcp_offset) {
  Ipv4 *iph = pkt->head_data<Ipv4 *>(ip_offset);
  Tcp *tcph = pkt->head_data<Tcp *>(tcp_offset);
  uint16_t payload_offset = tcp_offset + ((tcph->offset) << 2);
  uint32_t payload_size = pkt->total_len() - payload_offset;
//  assert(pkt->total_len() == pkt->head_len());

  bess::Packet *hugepkt = convert_to_huge_packet(pkt);
  if (unlikely(!hugepkt))
    return;
  if (likely(hugepkt!=pkt)) {
    bess::Packet::Free(pkt);
  }

  /* if TCP flags other than ACK are on, flush */
  if (tcph->flags & 0xef) {
    EmitPacket(ctx, hugepkt);
    flow->pkt = NULL;
    return;
  }

  flow->pkt = hugepkt;
  flow->tsc = rdtsc();
  flow->src_addr = iph->src.value();
  flow->dst_addr = iph->dst.value();
  flow->src_port = tcph->src_port.value();
  flow->dst_port = tcph->dst_port.value();
  flow->next_seq = tcph->seq_num.value() + payload_size;

  flow->ip_offset = ip_offset;
  flow->tcp_offset = tcp_offset;
  flow_count++;
}

void LRO::LroAppendPkt(Context *ctx, struct lro_flow *flow, bess::Packet *pkt, uint16_t ip_offset, uint16_t tcp_offset) {
  Ipv4 *iph = pkt->head_data<Ipv4 *>(ip_offset);
  Tcp *tcph = pkt->head_data<Tcp *>(tcp_offset);
  uint32_t payload_offset = tcp_offset + ((tcph->offset) << 2);
  uint32_t payload_size = pkt->total_len() - payload_offset;
//  assert(pkt->total_len() == pkt->head_len());
  uint32_t new_seq = tcph->seq_num.value();

  Ipv4 *old_ip = flow->pkt->head_data<Ipv4 *>(flow->ip_offset);
  Tcp *old_tcp = flow->pkt->head_data<Tcp *>(flow->tcp_offset);

  assert(pkt->is_linear());

  if (flow->next_seq != new_seq || old_tcp->ack_num.value() != tcph->ack_num.value()) {
    LroFlushFlow(ctx, flow);
    EmitPacketAfterConvert(ctx, pkt);
    return;
  }

  if (flow->pkt->total_len() + payload_size > 64000) {
    LroFlushFlow(ctx, flow);
    LroInitFlow(ctx, flow, pkt, ip_offset, tcp_offset);
    return;
  }

  // It is eligible to append packet payload.
  old_ip->length = be16_t(old_ip->length.value() + payload_size);
  old_tcp->flags |= tcph->flags;
  old_ip->type_of_service |= (iph->type_of_service & 0x3);

  pkt->adj(payload_offset);
  char *p = flow->pkt->head_data<char *>() + flow->pkt->total_len();
  flow->pkt->set_total_len(flow->pkt->total_len() + payload_size);
  flow->pkt->set_data_len(flow->pkt->data_len() + payload_size);
  bess::utils::Copy(p, pkt->head_data<char *>(), payload_size);
  bess::Packet::Free(pkt);

  /* if TCP flags other than ACK are on, flush */
  if (old_tcp->flags & 0xef) {
    LroFlushFlow(ctx, flow);
    return;
  }

  flow->next_seq = new_seq + payload_size;
}


void LRO::DoLro(Context *ctx, bess::Packet *pkt) {
  uint16_t ip_offset;
  uint16_t tcp_offset;

  int free_slot = -1;
  int i;

  /* skip checking whether packets are from physical intefaces and has correct csum */
  Ethernet *eth = pkt->head_data<Ethernet *>();
  void *data = eth + 1;

  if (eth->ether_type != be16_t(Ethernet::Type::kIpv4)) {
    EmitPacketAfterConvert(ctx, pkt);
    return;
  }

  Ipv4 *iph = reinterpret_cast<Ipv4 *>(data);
  size_t ip_bytes = (iph->header_length) << 2;
  
  if (iph->protocol != Ipv4::Proto::kTcp) {
    EmitPacketAfterConvert(ctx, pkt);
    return;
  }

  Tcp *tcph = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(iph) + ip_bytes);

  ip_offset = reinterpret_cast<uint8_t *>(iph) - reinterpret_cast<uint8_t *>(eth);
  tcp_offset = reinterpret_cast<uint8_t *>(tcph) - reinterpret_cast<uint8_t *>(eth);
  uint16_t payload_offset = tcp_offset + ((tcph->offset) << 2);
  uint32_t payload_size = pkt->total_len() - payload_offset;

  if (payload_size == 0) {
    EmitPacketAfterConvert(ctx, pkt);
    return;
  }

  for (i = 0; i < MAX_LRO_FLOWS; i++) {
    if (!worker_flows[i].pkt) {
      if (free_slot == -1)
        free_slot = i;
      continue;
    }
    if (worker_flows[i].src_addr == iph->src.value() &&
        worker_flows[i].dst_addr == iph->dst.value() &&
        worker_flows[i].src_port == tcph->src_port.value() &&
        worker_flows[i].dst_port == tcph->dst_port.value()) {
      LroAppendPkt(ctx, &worker_flows[i], pkt, ip_offset, tcp_offset);
      return;
    }
  }

  /* Here, there is no existing flow for the TCP packet. */
  /* Should we buffer this packet? */
  if (tcph->flags & 0xef) {
    /* Bypass if there are any flags other than ack */
    iph->checksum = CalculateIpv4Checksum(*iph);
    tcph->checksum = CalculateIpv4TcpChecksum(*iph, *tcph);

    EmitPacketAfterConvert(ctx, pkt);
    return;
  }

  if (free_slot == -1)
    free_slot = LroEvictFlow(ctx, worker_flows);
  LroInitFlow(ctx, &worker_flows[free_slot], pkt, ip_offset, tcp_offset);
}

ADD_MODULE(LRO, "lro", "Aggregate multiple incoming packets from a single stream into a larger buffer")