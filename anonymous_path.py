from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether

# packet
from ryu.lib.packet import packet, ethernet, arp, ipv4

# topo
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

import networkx as nx

class anonymous_path(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(anonymous_path, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.switch_map = {}
        self.host_fake_ip = {'10.0.0.1':'10.1.1.1',
                                '10.0.0.2':'10.2.2.2',
                                '10.0.0.3':'10.3.3.3',
                                '10.0.0.4':'10.4.4.4',
                                '10.0.0.5':'10.5.5.5',
                                '10.0.0.10':'10.8.8.8',
                                } 
        self.arp_table = {'10.0.0.1':'00:00:00:00:00:01',
                            '10.0.0.2':'00:00:00:00:00:02',
                            '10.0.0.3':'00:00:00:00:00:03',
                            '10.0.0.4':'00:00:00:00:00:04',
                            '10.0.0.5':'00:00:00:00:00:05',
                            '10.0.0.8':'00:00:00:00:00:06',
                            '10.0.0.10':'00:00:00:00:00:06'
                            }
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.switch_map.update({dp.id: dp})
        match = parser.OFPMatch()
        action = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)])
        inst = [action]
        self.add_flow(dp=dp, match=match, inst=inst, table=0, priority=1)

    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg= ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        
        ## parses the packet
        pkt = packet.Packet(data=msg.data)
        # ethernet
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return

        # filters LLDP packet 0x88CC
        if pkt_ethernet.ethertype == 35020:
            return
        
        # arp 0x0806
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_ethernet.ethertype == 2054:
            self.handle_arp(dp, in_port, pkt_ethernet, pkt_arp)
            return

        # ipv4 0x0800
        pkt_ip = pkt.get_protocol(ipv4.ipv4)

        # forwarded by shortest path
        if not self.net.has_node(pkt_ethernet.src):
            # print("add %s in self.net" % pkt_ethernet.src)
            self.net.add_node(pkt_ethernet.src)
            self.net.add_edge(pkt_ethernet.src, dp.id)
            self.net.add_edge(dp.id, pkt_ethernet.src, port=in_port)
            # print(self.net.nodes)
            # print(self.net.edges)
            
        if self.net.has_node(pkt_ethernet.dst):
            print("%s in self.net" % pkt_ethernet.dst)
            path = nx.shortest_path(self.net, pkt_ethernet.src, pkt_ethernet.dst)
            print(path)

            if pkt_ip.dst == '10.0.0.8':
                pkt_ip.dst = '10.0.0.10'
                # print(pkt_ip.dst)
            if pkt_ip.src == '10.0.0.10':
                pkt_ip.src = '10.0.0.8'
                # print(pkt_ip.src)

            if len(path) > 3:
                # print("more than two switch")
                for on_path_node in range(1, len(path)-1):
                    now_node = path[on_path_node]
                    next_node = path[on_path_node+1]
                    back_node = path[on_path_node-1]
                    next_port = self.net[now_node][next_node]['port']
                    back_port = self.net[now_node][back_node]['port']

                    if on_path_node == 1:
                        next_match = parser.OFPMatch(eth_type=0x0800, eth_src=pkt_ethernet.src, eth_dst=pkt_ethernet.dst)
                        next_action = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionSetField(ipv4_src=self.host_fake_ip[pkt_ip.src]), 
                                                                                            parser.OFPActionSetField(ipv4_dst=self.host_fake_ip[pkt_ip.dst]), 
                                                                                            parser.OFPActionOutput(next_port)])
                        
                        back_match = parser.OFPMatch(eth_type=0x0800, eth_src=pkt_ethernet.dst, eth_dst=pkt_ethernet.src)
                        back_action = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionSetField(ipv4_src=pkt_ip.dst), 
                                                                                            parser.OFPActionSetField(ipv4_dst=pkt_ip.src), 
                                                                                            parser.OFPActionOutput(back_port)])
                        inst = [next_action]
                        self.add_flow(dp=self.switch_map[now_node], match=next_match, inst=inst)
                        inst = [back_action]
                        self.add_flow(dp=self.switch_map[now_node], match=back_match, inst=inst)                        

                    elif on_path_node == len(path)-2:
                        next_match = parser.OFPMatch(eth_type=0x0800, eth_src=pkt_ethernet.src, eth_dst=pkt_ethernet.dst)
                        next_action = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionSetField(ipv4_src=pkt_ip.src),
                                                                                            parser.OFPActionSetField(ipv4_dst=pkt_ip.dst),
                                                                                            parser.OFPActionOutput(next_port)])
                        back_match = parser.OFPMatch(eth_type=0x0800, eth_src=pkt_ethernet.dst, eth_dst=pkt_ethernet.src)
                        back_action = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionSetField(ipv4_src=self.host_fake_ip[pkt_ip.dst]),
                                                                                            parser.OFPActionSetField(ipv4_dst=self.host_fake_ip[pkt_ip.src]),
                                                                                            parser.OFPActionOutput(back_port)])
                        inst = [next_action]
                        self.add_flow(dp=self.switch_map[now_node], match=next_match, inst=inst)
                        inst = [back_action]
                        self.add_flow(dp=self.switch_map[now_node], match=back_match, inst=inst)

                    else:
                        next_match = parser.OFPMatch(eth_dst=pkt_ethernet.dst)
                        next_action = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(next_port)])
                        back_match = parser.OFPMatch(eth_dst=pkt_ethernet.src)
                        back_action = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(back_port)])
                        inst = [next_action]
                        self.add_flow(dp=self.switch_map[now_node], match=next_match, inst=inst, priority=10)
                        inst = [back_action]
                        self.add_flow(dp=self.switch_map[now_node], match=back_match, inst=inst, priority=10)
                    # print("now switch: %s" % now_switch)

            else: ########### 還沒匿名
                # print("one switch only")
                now_switch = path[1]
                src_host = path[0]
                dst_host = path[2]
                next_port = self.net[now_switch][dst_host]['port']
                back_port = self.net[now_switch][src_host]['port']

                next_match = parser.OFPMatch(eth_src=pkt_ethernet.src, eth_dst=pkt_ethernet.dst)
                action = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(next_port)])
                inst = [action]
                self.add_flow(dp=self.switch_map[now_switch], match=next_match, inst=inst)

                back_match = parser.OFPMatch(eth_src=pkt_ethernet.dst, eth_dst=pkt_ethernet.src)
                action = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(back_port)])
                inst = [action]
                self.add_flow(dp=self.switch_map[now_switch], match=back_match, inst=inst)

        else:
            return

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        print("switches: %s" % switches)
        print("links:%s" % links)		
        self.net.add_nodes_from(switches)
        self.net.add_edges_from(links)

    def add_flow(self, dp, cookie=0, match=None, inst=[], table=0, priority=20):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        buffer_id = ofp.OFP_NO_BUFFER

        mod = parser.OFPFlowMod(
                datapath=dp, cookie=cookie, table_id=table,
                command=ofp.OFPFC_ADD, priority=priority, buffer_id=buffer_id,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=match, instructions=inst
        )
        dp.send_msg(mod)

    def send_packet(self, dp, port, pkt):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt.serialize()
        data = pkt.data
        test_pkt = packet.Packet(data) ###
        test_eth_pkt = test_pkt.get_protocol(ethernet.ethernet) ###
        action = [parser.OFPActionOutput(port=port)]

        out = parser.OFPPacketOut(
                datapath=dp, buffer_id = ofproto.OFP_NO_BUFFER,
                in_port = ofproto.OFPP_CONTROLLER,
                actions=action, data=data)
        # print("send back arp to %s" % test_eth_pkt.dst) ###
        dp.send_msg(out)

    def handle_arp(self, dp, port, pkt_ethernet, pkt_arp):
        print("%s request arp to %s" % (pkt_arp.src_ip, pkt_arp.dst_ip)) ###
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        
        if self.arp_table.get(pkt_arp.dst_ip) == None:
            return
        get_mac = self.arp_table[pkt_arp.dst_ip]
        
        # controller sends back the arp rely to the requesting host
        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                ethertype=ether.ETH_TYPE_ARP,
                dst = pkt_ethernet.src,
                src = get_mac
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

        self.send_packet(dp, port, pkt)