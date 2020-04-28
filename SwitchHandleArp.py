from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import mac_to_port
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4

from ryu.topology import event
from ryu.topology.api import get_switch, get_link

class SwitchHandleArp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchHandleArp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.arp_table = {'10.0.0.1':'00:00:00:00:00:01',
                          '10.0.0.2':'00:00:00:00:00:02',
                          '10.0.0.3':'00:00:00:00:00:03',
                          '10.0.0.4':'00:00:00:00:00:04'}

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        link_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid) for link in link_list]

        print('switches: %s' %switches)
        print('links: %s' %links)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        # install table-miss flow entry
        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, 
                                              ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, 0, match, actions)

    def add_flow(self, datapath, table, priority, match, actions):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    table_id=table, match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

    def send_packet(self, datapath, port, pkt):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data

        actions = [ofp_parser.OFPActionOutput(port=port)]

        out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port = ofp.OFPP_CONTROLLER,actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return

        # filter LLDP packet 0x88CC
        if pkt_ethernet.ethertype == 35020:
            return

        # handle arp packet 0x0806
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_ethernet.ethertype == 2054:
            self.handle_arp(dp, in_port, pkt_ethernet, pkt_arp)
            return

        src_mac = pkt_ethernet.src
        dst_mac = pkt_ethernet.dst


        # initialize the mac_to_port dictionary
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in dpid:%s src_mac:%s dst_mac:%s port:%s", dpid, src_mac, dst_mac, in_port)

        # learn a mac address to avoid FLOOD next time
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [ofp_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofp.OFPP_FLOOD:
            match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(dp, 0, 1, match, actions)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    def handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        
        if self.arp_table.get(pkt_arp.dst_ip) == None:
            return
        get_mac = self.arp_table[pkt_arp.dst_ip]

        # send back arp_rely to requesting host
        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                ethertype = 2054,
                src = get_mac,
                dst = pkt_ethernet.src
            )
        )

        pkt.add_protocol(
            arp.arp(
                opcode = arp.ARP_REPLY,
                src_mac= get_mac,
                src_ip = pkt_arp.dst_ip,
                dst_mac= pkt_arp.src_mac,
                dst_ip = pkt_arp.src_ip
            )
        )

        self.send_packet(datapath, port, pkt)