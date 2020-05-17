from ryu.base import app_manager
from ryu.controller import ofp_event
# from ryu.controller import mac_to_port
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, ipv6

from ryu.lib.mac import haddr_to_bin
# from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.app.wsgi import ControllerBase
from ryu.topology import event
# from ryu.topology.api import get_switch, get_link
from collections import defaultdict
from operator import itemgetter

import os
import random
import time

REFERENCE_BW = 10000000
DEFAULT_BW = 10000000
MAX_PATHS = 2
FAKE_IP_NUMBER = 2

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        # self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        # self.arp_table = {}
        self.arp_table = {'10.0.0.1':'00:00:00:00:00:01',
                            '10.0.0.2':'00:00:00:00:00:02',
                            '10.0.0.3':'00:00:00:00:00:03',
                            '10.0.0.4':'00:00:00:00:00:04'}
        self.switches = []
        self.hosts = {}
        self.host_ips = set()
        self.multipath_group_ids = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))
        self.fake_ips = defaultdict(dict)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        print('switch', dp.id, 'enter')

        # install table-miss flow entry
        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, 
                                              ofp.OFPCML_NO_BUFFER)]
        self.add_flow(datapath=dp, table=0, priority=0, 
                        timeout=0, match=match, actions=actions)

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
        print('add link', s1.dpid, 'and',s2.dpid)

    def get_paths(self, src_switch, dst_switch, ip_src, ip_dst):
        '''
        Get all paths from src to dst using DFS algorithm    
        '''
        if src_switch == dst_switch:
            # host target is on the same switch
            print(ip_src, "and", ip_dst, "on the same switch")
            return [[src_switch]]
        paths = []
        stack = [(src_switch, [src_switch])]
        while stack:
            (node, path) = stack.pop()
            for next in set(self.adjacency[node].keys()) - set(path):
                if next is dst_switch:
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

    def get_optimal_paths(self, src_switch, dst_switch, ip_src, ip_dst):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src_switch, dst_switch, ip_src, ip_dst)
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

    def generate_gid(self):
        '''
        Return a random OpenFlow group id
        '''
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        self.group_ids.append(n)
        return n

    def add_flow(self, datapath, table, priority, timeout, match, actions):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    table_id=table, match=match,
                                    idle_timeout=timeout, instructions=inst)
        datapath.send_msg(mod)

    def fake_ip_generator(self, real_ip):
        '''
        Generate several fake IPs for host
        '''
        self.fake_ips[real_ip]['fake_ip'] = []

        i = 0
        while i < FAKE_IP_NUMBER:
            fake_ip = str(random.randint(1, 255))
            for j in range(3):
                n = random.randint(1, 255)
                fake_ip = fake_ip + '.' + str(n)

            if fake_ip not in self.host_ips:
                self.fake_ips[real_ip]['fake_ip'].append(fake_ip)                
                i += 1

        self.fake_ips[real_ip]['time'] = time.time()        
        
        #  也要檢查是否在 self.fake_ips 的 value 裡
        # 

    def handle_fake_ip(self,real_ip):
        '''
        Check if fake IPs are available
        '''
        if 'time' not in self.fake_ips[real_ip].keys():
            self.fake_ips[real_ip]['group_id'] = self.generate_gid()
            self.fake_ip_generator(real_ip)

        elif time.time() - self.fake_ips[real_ip]['time'] > 300:
            self.fake_ip_generator(real_ip)
    
    def install_paths(self, src_switch, first_port, dst_switch, last_port, src_mac, dst_mac, ip_src, ip_dst):
        # computation_start = time.time()
        paths = self.get_optimal_paths(src_switch, dst_switch, ip_src, ip_dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            print(path, "cost =", pw[len(pw)-1])
        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)

        # handle_fake_ip(ip_src)
        # handle_fake_ip(ip_dst)
        self.fake_ip_generator(ip_src)
        self.fake_ips[ip_src]['group_id'] = self.generate_gid()
        self.fake_ip_generator(ip_dst)
        self.fake_ips[ip_dst]['group_id'] = self.generate_gid()

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            output_group_id = None
            group_new = False
            if (node, src_switch, dst_switch) not in self.multipath_group_ids:
                group_new = True
                self.multipath_group_ids[node, src_switch, dst_switch] = self.generate_gid()
            output_group_id = self.multipath_group_ids[node, src_switch, dst_switch]

            # Add group table: change src ip
            buckets = []
            for s in range(FAKE_IP_NUMBER):
                bucket_action = [ofp_parser.OFPActionSetField(ipv4_src=self.fake_ips[ip_src]['fake_ip'][s]),
                                ofp_parser.OFPActionGroup(self.fake_ips[ip_dst]['group_id'])]
                buckets.append(ofp_parser.OFPBucket(actions=bucket_action))
            req = ofp_parser.OFPGroupMod(
                dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, self.fake_ips[ip_src]['group_id'],
                buckets
            )
            dp.send_msg(req)

            # Add group table: change dst ip
            buckets = []
            for d in range(FAKE_IP_NUMBER):
                bucket_action = [ofp_parser.OFPActionSetField(ipv4_dst=self.fake_ips[ip_dst]['fake_ip'][d]),
                                ofp_parser.OFPActionGroup(output_group_id)]
                buckets.append(ofp_parser.OFPBucket(actions=bucket_action))
            req = ofp_parser.OFPGroupMod(
                dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, self.fake_ips[ip_dst]['group_id'],
                buckets
            )
            dp.send_msg(req)

            match_real_ip = ofp_parser.OFPMatch(
                eth_type=0x0800, 
                ipv4_src=ip_src, 
                ipv4_dst=ip_dst
            )
            match_fake_ip = []
            for m in range(FAKE_IP_NUMBER):
                for n in range(FAKE_IP_NUMBER):
                    match_fake_ip.append(
                        ofp_parser.OFPMatch(
                            eth_type = 0x0800,
                            ipv4_src = self.fake_ips[ip_src]['fake_ip'][m],
                            ipv4_dst = self.fake_ips[ip_dst]['fake_ip'][n]
                        )
                    )

            ports = defaultdict(list)            
            i = 0

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                i += 1

            for in_port in ports:
                out_ports = ports[in_port]

                if len(out_ports) > 1:
                    buckets = []
                    for port, weight in out_ports:
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                actions=bucket_action
                            )
                        )
                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, output_group_id,
                            buckets)
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT, output_group_id,
                            buckets)
                        dp.send_msg(req)

                elif len(out_ports) == 1:
                    bucket = [ofp_parser.OFPBucket(actions=[ofp_parser.OFPActionOutput(out_ports[0][0])])]
                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_INDIRECT, output_group_id,
                            bucket)
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_INDIRECT, output_group_id,
                            bucket)
                        dp.send_msg(req)
            
            for j in range(len(paths)):
                actions = []
                if len(paths[j]) > 1:
                    if node == paths[j][0]:
                        actions.append(ofp_parser.OFPActionSetField(eth_src='00:00:00:00:00:00'))
                        actions.append(ofp_parser.OFPActionSetField(eth_dst='00:00:00:00:00:00'))
                        actions.append(ofp_parser.OFPActionGroup(self.fake_ips[ip_src]['group_id']))
                        self.add_flow(datapath=dp, table=0, priority=32768, 
                                        timeout=300, match=match_real_ip, actions=actions)
                    elif node == paths[j][-1]:
                        actions.append(ofp_parser.OFPActionSetField(eth_src=src_mac))
                        actions.append(ofp_parser.OFPActionSetField(eth_dst=dst_mac))
                        actions.append(ofp_parser.OFPActionSetField(ipv4_src=ip_src))
                        actions.append(ofp_parser.OFPActionSetField(ipv4_dst=ip_dst))
                        actions.append(ofp_parser.OFPActionGroup(output_group_id))
                        for k in range(FAKE_IP_NUMBER**2):
                            self.add_flow(datapath=dp, table=0, priority=32768, 
                                            timeout=300, match=match_fake_ip[k], actions=actions)
                    elif node in paths[j]:
                        actions.append(ofp_parser.OFPActionGroup(self.fake_ips[ip_src]['group_id']))
                        for l in range(FAKE_IP_NUMBER**2):
                            self.add_flow(datapath=dp, table=0, priority=32768, 
                                            timeout=300, match=match_fake_ip[l], actions=actions)
                else:
                    actions.append(ofp_parser.OFPActionOutput(paths_with_ports[j][node][1]))
                    self.add_flow(datapath=dp, table=0, priority=32768, 
                                    timeout=300, match=match_real_ip, actions=actions)

        # print("Path installation finished in ", time.time()-computation_start)
        print('install path', ip_src, 'to', ip_dst)
        return paths_with_ports[0][src_switch][1]

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
            self.add_flow(datapath=dp, table=0, priority=1, 
                            timeout=0, match=match, actions=actions)
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
            # self.arp_table[pkt_arp.src_ip] = src_mac ##################
            self.host_ips.add(pkt_arp.src_ip)
            self.host_ips.add(pkt_arp.dst_ip)
            self.handle_arp(dp, in_port, pkt_ethernet, pkt_arp)
            return

        # initialize the mac_to_port dictionary
        # dpid = dp.id
        # self.mac_to_port.setdefault(dpid, {})

        out_port = ofp.OFPP_FLOOD

        # get packet ip address 0x0800
        if pkt.get_protocol(ipv4.ipv4):
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst            
            if dst_mac in self.hosts:
                h1 = self.hosts[src_mac]
                h2 = self.hosts[dst_mac]
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], 
                                                src_mac, dst_mac, src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1],
                                    dst_mac, src_mac, dst_ip, src_ip) # reverse

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

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print(ev)
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        # Exception handling if switch already deleted
        try:
            del self.adjacency[s1.dpid][s2.dpid]
            del self.adjacency[s2.dpid][s1.dpid]
        except KeyError:
            pass