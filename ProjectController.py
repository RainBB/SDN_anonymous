from ryu.base import app_manager
from ryu.controller import ofp_event
# from ryu.controller import mac_to_port
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, ipv6

# from ryu.lib.mac import haddr_to_bin
# from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.app.wsgi import ControllerBase
from ryu.topology import event
# from ryu.topology.api import get_switch, get_link
from collections import defaultdict
from operator import itemgetter

import os
import random
# import time

REFERENCE_BW = 10000000
DEFAULT_BW = 10000000
MAX_PATHS = 2

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        # self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}        
        self.arp_table = {'10.0.0.1':'00:00:00:00:00:01',
                          '10.0.0.2':'00:00:00:00:00:02',
                          '10.0.0.3':'00:00:00:00:00:03',
                          '10.0.0.4':'00:00:00:00:00:04'}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))

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

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch

            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

    def get_paths(self, src, dst, ip_src, ip_dst):
        '''
        Get all paths from src to dst using DFS algorithm    
        '''
        if src == dst:
            # host target is on the same switch
            print(ip_src, "and", ip_dst, "on the same switch")
            return [[src]]
        paths = []
        stack = [(src, [src])]
        while stack:
            (node, path) = stack.pop()
            for next in set(self.adjacency[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                else:
                    stack.append((next, path + [next]))
        print("Available paths from", ip_src, "to", ip_dst, ":", paths)
        return paths

    def get_link_cost(self, s1, s2):
        '''
        Get the link cost between two switches 
        '''
        p1 = self.adjacency[s1][s2]
        p2 = self.adjacency[s2][s1]
        bl = min(self.bandwidths[s1][p1], self.bandwidths[s2][p2])
        ew = REFERENCE_BW/bl
        return ew

    def get_path_cost(self, path):
        '''
        Get the path cost
        '''
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        return cost

    def get_optimal_paths(self, src, dst, ip_src, ip_dst):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst, ip_src, ip_dst)
        paths_count = len(paths) if len(paths) < MAX_PATHS else MAX_PATHS
        return sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]

    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        '''
        Returns a random OpenFlow group id
        '''
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        return n

    def add_flow(self, datapath, table, priority, match, actions):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    table_id=table, match=match,
                                    idle_timeout=60, instructions=inst)
        datapath.send_msg(mod)

    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        # computation_start = time.time()
        paths = self.get_optimal_paths(src, dst, ip_src, ip_dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            print(path, "cost =", pw[len(pw)-1])
        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            actions = []
            i = 0

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                i += 1

            for in_port in ports:

                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                out_ports = ports[in_port]
                # print(out_ports) 

                if len(out_ports) > 1:
                    group_id = None
                    group_new = False

                    if (node, src, dst) not in self.multipath_group_ids:
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst] = self.generate_openflow_gid()
                    group_id = self.multipath_group_ids[node, src, dst]

                    buckets = []
                    # print("node at", node, "out ports :", out_ports)
                    for port, weight in out_ports:
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )

                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT, group_id,
                            buckets)
                        dp.send_msg(req)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 0, 32768, match_ip, actions)
                    self.add_flow(dp, 0, 1, match_arp, actions)

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                    self.add_flow(dp, 0, 32768, match_ip, actions)
                    self.add_flow(dp, 0, 1, match_arp, actions)
        # print("Path installation finished in ", time.time()-computation_start)
        print("install path")
        return paths_with_ports[0][src][1]


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

        # filter LLDP packets 0x88CC
        if pkt_ethernet.ethertype == 35020:
            return

        # drop IPV6 packets
        if pkt.get_protocol(ipv6.ipv6):
            match = ofp_parser.OFPMatch(eth_type=pkt_ethernet.ethertype)
            actions = []
            self.add_flow(dp, 0, 1, match, actions)
            return None

        src_mac = pkt_ethernet.src
        dst_mac = pkt_ethernet.dst
        dpid = dp.id

        # build up hosts[]
        if src_mac not in self.hosts:
            self.hosts[src_mac] = (dpid, in_port)

        # handle ARP packets 0x0806
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_ethernet.ethertype == 2054:
            self.handle_arp(dp, in_port, pkt_ethernet, pkt_arp)
            return


        # initialize the mac_to_port dictionary
        # dpid = dp.id
        # self.mac_to_port.setdefault(dpid, {})
        # self.logger.info("packet in dpid:%s src_mac:%s dst_mac:%s port:%s", dpid, src_mac, dst_mac, in_port)


        out_port = ofp.OFPP_FLOOD

        # get packet ip address 0x0800
        if pkt.get_protocol(ipv4.ipv4):
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst
            h1 = self.hosts[src_mac]
            h2 = self.hosts[dst_mac]
            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse


        # if pkt_arp:
        #     src_ip = pkt_arp.src_ip
        #     dst_ip = pkt_arp.dst_ip
        #     if pkt_arp.opcode == arp.ARP_REPLY:
        #         self.arp_table[src_ip] = src_mac
        #         h1 = self.hosts[src_mac]
        #         h2 = self.hosts[dst_mac]
        #         out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
        #         self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
        #     elif pkt_arp.opcode == arp.ARP_REQUEST:
        #         if dst_ip in self.arp_table:
        #             self.arp_table[src_ip] = src_mac
        #             get_mac = self.arp_table[dst_ip]
        #             h1 = self.hosts[src_mac]
        #             h2 = self.hosts[get_mac]
        #             out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
        #             self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse


        actions = [ofp_parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    def send_packet(self, datapath, port, pkt):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data

        actions = [ofp_parser.OFPActionOutput(port=port)]

        out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port = ofp.OFPP_CONTROLLER,actions=actions, data=data)
        datapath.send_msg(out)

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




    # @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    # def switch_leave_handler(self, ev):
    #     print(ev)
    #     switch = ev.switch.dp.id
    #     if switch in self.switches:
    #         self.switches.remove(switch)
    #         del self.datapath_list[switch]
    #         del self.adjacency[switch]

    # @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    # def link_delete_handler(self, ev):
    #     s1 = ev.link.src
    #     s2 = ev.link.dst
    #     # Exception handling if switch already deleted
    #     try:
    #         del self.adjacency[s1.dpid][s2.dpid]
    #         del self.adjacency[s2.dpid][s1.dpid]
    #     except KeyError:
    #         pass