import csv
from collections import defaultdict

from scapy.sessions import DefaultSession

from features.context.packet_direction import PacketDirection
from features.context.packet_flow_key import get_packet_flow_key
from flow import Flow
import gc

EXPIRED_UPDATE = 40
MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 100

srcs = ['10.201.', '10.203.', '223.3.', '2001:da8:1002:6001::2:ed29', '172.17.']

class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0

        if self.output_mode == "flow":
            output = open(self.output_file, "a+")
            self.csv_writer = csv.writer(output)

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        # self.garbage_collect(None) # 只有结束时才GC
        self.gc() # 只有结束时才GC
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != "flow":
            if "TCP" not in packet:
                return
            elif "UDP" not in packet:
                return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return
        
        if self.protocol not in packet:
            return
        # 只记录向前的包
        if not is_fwd(packet["IP"].src):
            return

        self.packets_count += 1

        if len(packet[self.protocol].payload) == 0:
            # print("空包")
            return

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            self.flows[(packet_flow_key, count)] = flow

        # elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
        #     # If the packet exists in the flow but the packet is sent
        #     # after too much of a delay than it is a part of a new flow.
        #     expired = EXPIRED_UPDATE
        #     while (packet.time - flow.latest_timestamp) > expired:
        #         count += 1
        #         expired += EXPIRED_UPDATE
        #         flow = self.flows.get((packet_flow_key, count))

        #         if flow is None:
        #             flow = Flow(packet, direction)
        #             self.flows[(packet_flow_key, count)] = flow
        #             break
        # elif "F" in str(packet.flags):
        #     # If it has FIN flag then early collect flow and continue
        #     flow.add_packet(packet, direction)
        #     # self.garbage_collect(packet.time)
        #     return

        # 限制包数量
        if self.protocol == 'TCP' and flow.upload_num >= self.upper_num:
            return
        # if flow.upload_num >= self.upper_num:
        #     return        
        

        flow.add_packet(packet, direction)

        if not self.url_model:
            # GARBAGE_COLLECT_PACKETS = 10000
            GARBAGE_COLLECT_PACKETS = 20000

        # if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
        #     flow.duration > 120 and self.output_mode == "flow"
        # ):
        #     self.garbage_collect(packet.time)

        if self.protocol == 'UDP' and (flow.upload_num >= self.upper_num or self.packets_count % GARBAGE_COLLECT_PACKETS == 0):
            # print('gc~~~~~~~~~~~~~~')
            self.gc(packet.time)
            if (self.packets_count % GARBAGE_COLLECT_PACKETS == 0):
                print(self.packets_count, 'packs -> gc ', gc.collect())
                

    def get_flows(self) -> list:
        return self.flows.values()

    # 按照包数量gc
    def gc(self, latest_time=None):
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)
            if not is_fwd(flow.src_ip):
                continue

            
            # 只记录达到upper_num数量的连接信息
            if flow.upload_num == self.upper_num:
                data = flow.get_data()

                # 头单独记录
                # if self.csv_line == 0:
                #     self.csv_writer.writerow(data.keys())
                # print('write a record')
                self.csv_writer.writerow(data.values())
                self.csv_line += 1

                del self.flows[k]
            elif (
                latest_time is not None
                and latest_time - flow.latest_timestamp > EXPIRED_UPDATE
            ):
                del self.flows[k]
        # gc.collect()
        # print('gc ok')

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        # if not self.url_model:
        #     print("Garbage Collection Began. Flows = {}".format(len(self.flows)))
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)

            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 90
            ):
                data = flow.get_data()

                if self.csv_line == 0:
                    self.csv_writer.writerow(data.keys())

                self.csv_writer.writerow(data.values())
                self.csv_line += 1

                del self.flows[k]
        # if not self.url_model:
        #     print("Garbage Collection Finished. Flows = {}".format(len(self.flows)))


def generate_session_class(output_mode, output_file, url_model, upper_num=100, proto='TCP' ):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_mode": output_mode,
            "output_file": output_file,
            "url_model": url_model,
            "upper_num": upper_num,
            "protocol": proto,
        },
    )


def is_fwd(src: str):
    for x in srcs:
        if src.find(x) != -1:
            return True
    return False