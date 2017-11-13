#![allow(unused_mut)]
//#![allow(unused_variables)]
#![allow(dead_code)]

extern crate pnet;
extern crate pcap_file;
//stander library
use std::fs::File;
use std::net::IpAddr;
use std::ops::Deref;
use std::ops::DerefMut;
use std::collections::HashMap;
//pcap_file
use pcap_file::PcapReader;
//pnet
use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

struct PacketItem {
    pkt_sec: u32,
    pkt_len: u32,
    ip_src: IpAddr,
    sport: u16,
    ip_dst: IpAddr,
    dport: u16,
    proto: u8,
}

struct FlowItem {
    //1.connection metric 9 种
    duration: i32,
    protocol_type: u8,  //协议类型，离散类型，共有3种：TCP, UDP, ICMP
    service: u8,        //目标主机的网络服务类型,共有70种
    tcp_flag: u8,       //连接正常或错误的状态,共11种
    src_bytes: u32,     //从源主机到目标主机的数据的字节数，连续类型，范围是 [0, 1379963888]。
    dst_bytes: u32,     //从目标主机到源主机的数据的字节数，连续类型，范围是 [0. 1309937401]
    land: u8,           //若连接来自/送达同一个主机/端口则为1，否则为0，离散类型，0或1
    wrong_fragment:u8,  //错误分段的数量，连续类型，范围是 [0, 3]。
    urgent: u8,         //加急包的个数，连续类型，范围是[0, 14]。

    //3.time metric 9种
    count: u32,             //过去两秒内，与当前连接具有相同的目标主机的连接数，连续，[0, 511]
    srv_count: u32,         //过去两秒内，与当前连接具有相同服务的连接数，连续，[0, 511]
    serror_rate: u8,        //过去两秒内，在与当前连接具有相同目标主机的连接中，出现“SYN” 错误的连接的百分比，连续，[0.00, 1.00]
    srv_serror_rate: u8,    //过去两秒内，在与当前连接具有相同服务的连接中，出现“SYN” 错误的连接的百分比，连续，[0.00, 1.00]
    rerror_rate: u8,        //过去两秒内，在与当前连接具有相同目标主机的连接中，出现“REJ” 错误的连接的百分比，连续，[0.00, 1.00]
    srv_rerror_rate: u8,    //过去两秒内，在与当前连接具有相同服务的连接中，出现“REJ” 错误的连接的百分比
    same_srv_rate: u8,      //过去两秒内，在与当前连接具有相同目标主机的连接中，与当前连接具有相同服务的连接的百分比
    diff_srv_rate: u8,      //过去两秒内，在与当前连接具有相同目标主机的连接中，与当前连接具有不同服务的连接的百分比
    srv_diff_host_rate: u8, //过去两秒内，在与当前连接具有相同服务的连接中，与当前连接具有不同目标主机的连接的百分比
    //4 10种
    dst_host_count: u8,             //100connections, same target
    dst_host_srv_count: u8,         //100 connections, same target,same service
    dst_host_same_srv_rate: u8,     //100 connections, same target, same service percent
    dst_host_diff_srv_rate: u8,     //100 connections,  same target ,diff service percent
    dst_host_same_src_port_rate: u8,//100 connections, same target, same sport persent
    dst_host_srv_diff_host_rate: u8,//100 connections,
    dst_host_serror_rate: u8,       //前100个连接中，与当前连接具有相同目标主机的连接中，出现SYN错误的连接所占的百分比
    dst_host_srv_serror_rate: u8,   //前100个连接中，与当前连接具有相同目标主机相同服务的连接中，出现SYN错误的连接所占的百分比
    dst_host_rerror_rate: u8,       //前100个连接中，与当前连接具有相同目标主机的连接中，出现REJ错误的连接所占的百分比，连续
    dst_host_srv_rerror_rate:u8,    //前100个连接中，与当前连接具有相同目标主机相同服务的连接中，出现REJ错误的连接所占的百分比
}
//Pcap packet list for parser
struct PacketList(Vec<PacketItem>);
impl Deref for PacketList {
    type Target = Vec<PacketItem>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for PacketList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
//KDD data fomat result
struct FlowList(Vec<FlowItem>);

impl Deref for FlowList {
    type Target = Vec<FlowItem>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for FlowList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FlowList {
    fn new() -> Self{
        FlowList(Vec::<FlowItem>::new())
    }
}

impl PacketList {
    fn new() -> Self {
        PacketList(Vec::<PacketItem>::new())
    }
}
fn main() {
    let mut packet_count = 0;
    let mut packet_list = PacketList::new();
    let mut flow_list = FlowList::new();

    println!("Start to parser Pcap file:{}", "test.pcap\n");
    let file_in = File::open("test.pcap").expect("Error opening file");
    let pcap_reader = PcapReader::new(file_in).unwrap();

    for pcap in pcap_reader {
        let pkt = EthernetPacket::new(&pcap.data).unwrap();
        if let Some(mut packet_item) = handle_packet(&pkt) {
            #[cfg(debug_assertions)]{
                println!("parser packet:{} {}:{} -> {}:{}",
                         packet_item.proto,
                         packet_item.ip_src,
                         packet_item.sport,
                         packet_item.ip_dst,
                         packet_item.dport);
            }
            packet_item.pkt_sec = pcap.header.ts_sec;
            packet_item.pkt_len = pcap.header.orig_len;
            packet_list.push(packet_item);
        }
        packet_count += 1;
    }

    let parser_count = packet_list.len();
    println!("Read Pcap file {} packets complete,{} packet handled, start convert to KDD data set", packet_count, parser_count);

    let mut flow_hash: HashMap<FlowKey, PacketList> = HashMap::new();
    flow_parser(&mut flow_hash,packet_list);

    #[cfg(debug_assertions)] {
        println!("\n[flow table]");
        for key in flow_hash.keys() {
            println!("proto:{} src:{} sport:{} -> dst:{} dport:{}", key.proto, key.src, key.sport, key.dst, key.dport);
            for pkt in flow_hash.get(key).unwrap().iter() {
                println!("\ttime:{}, len:{:>5} packet:{:>2} {:>15}:{:<5} -> {:>15}:{:<5}",pkt.pkt_sec, pkt.pkt_len, pkt.proto, pkt.ip_src, pkt.sport, pkt.ip_dst, pkt.dport);
            }
        }
    }

    

    println!("pcap packets:{}, parser:{} packets, generate {} KDD items",packet_count, parser_count, flow_list.len() );
}


//5-tuple hash key
#[derive(Eq, Hash)]
struct FlowKey {
    src: u32,
    sport: u16,
    dst: u32,
    dport: u16,
    proto: u8,
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &FlowKey) -> bool {
        if self.src == other.src &&
            self.dst == other.dst &&
            self.sport == other.sport &&
            self.dport == other.dport &&
            self.proto == other.proto {
            true
        } else if
            self.src == other.dst &&
                self.dst == other.src &&
                self.sport == other.dport &&
                self.dport == other.sport &&
                self.proto == other.proto {
            true
        } else {
            false
        }
    }
}

fn flow_parser(flow_hash: &mut HashMap<FlowKey, PacketList>,packet_list: PacketList) {

    for pkt in packet_list.iter() {
        let ipv4addr_src_u32: u32;
        let ipv4addr_dst_u32: u32;

        match pkt.ip_src {
            IpAddr::V4(ipv4addr_src) => {
                ipv4addr_src_u32 = ipv4addr_src.into();
            }
            _ => continue
        }
        match pkt.ip_dst {
            IpAddr::V4(ipv4addr_dst) => {
                ipv4addr_dst_u32 = ipv4addr_dst.into();
            }
            _ => continue
        }

        let key = FlowKey {
            src: ipv4addr_src_u32,
            sport: pkt.sport,
            dst: ipv4addr_dst_u32,
            dport: pkt.dport,
            proto: pkt.proto,
        };
        //add to flow hash table
        let mut pkt_list = flow_hash.entry(key).or_insert(PacketList::new());
        pkt_list.push(PacketItem{..*pkt});
    }
}

fn handle_transport_protocol( source: IpAddr,
                             destination: IpAddr,
                             protocol: IpNextHeaderProtocol,
                             packet: &[u8]) -> Option<PacketItem> {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet( source, destination, packet)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet( source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet( source, destination, packet)
        }
        //IpNextHeaderProtocols::Icmpv6 => {
        //    handle_icmpv6_packet(source, destination, packet)
        //}
        _ => {
            None
        }
    }
}

fn handle_udp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) -> Option<PacketItem>{
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {

        Some(PacketItem{pkt_sec: 0u32,
                        pkt_len: 0u32,
                        ip_src: source,
                        sport: udp.get_source() as u16,
                        ip_dst: destination,
                        dport: udp.get_destination() as u16,
                        proto: IpNextHeaderProtocols::Udp.0 as u8,

        })
    } else {
        None
    }
}
fn handle_ipv4_packet( ethernet: &EthernetPacket) -> Option<PacketItem>{
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(  IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload())
    } else {
        None
    }
}

fn handle_ipv6_packet( ethernet: &EthernetPacket) -> Option<PacketItem>{
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(IpAddr::V6(header.get_source()),
                                  IpAddr::V6(header.get_destination()),
                                  header.get_next_header(),
                                  header.payload())
    } else {
        None
    }
}

fn handle_arp_packet( ethernet: &EthernetPacket) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        println!("ARP packet: {}({}) > {}({}); operation: {:?}",
                 ethernet.get_source(),
                 header.get_sender_proto_addr(),
                 ethernet.get_destination(),
                 header.get_target_proto_addr(),
                 header.get_operation());
    } else {
        println!("Malformed ARP Packet");
    }
}

fn handle_packet(ethernet: &EthernetPacket) -> Option<PacketItem> {

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet),

        //do not handle ipv6 just now,supported later
        //EtherTypes::Ipv6 => handle_ipv6_packet( ethernet),
        //EtherTypes::Arp => handle_arp_packet( ethernet),
        _ => None
    }
}

fn handle_icmp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) -> Option<PacketItem>{
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(_) = icmp_packet {

        Some(PacketItem{pkt_sec: 0u32,
            pkt_len: 0u32,
            ip_src: source,
            sport: 0u16,
            ip_dst: destination,
            dport: 0u16,
            proto: IpNextHeaderProtocols::Icmp.0 as u8,

        })
    } else {
        None
    }
}

fn handle_icmpv6_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) -> Option<PacketItem>{
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(_) = icmpv6_packet {

        Some(PacketItem{pkt_sec: 0u32,
            pkt_len: 0u32,
            ip_src: source,
            sport: 0u16,
            ip_dst: destination,
            dport: 0u16,
            proto: IpNextHeaderProtocols::Icmp.0 as u8,
        })
    } else {
        None
    }
}

fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) -> Option<PacketItem>{
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {

        Some(PacketItem{pkt_sec: 0u32,
            pkt_len: 0u32,
            ip_src: source,
            sport: tcp.get_source() as u16,
            ip_dst: destination,
            dport: tcp.get_destination() as u16,
            proto: IpNextHeaderProtocols::Tcp.0 as u8,

        })
    } else {
        None
    }
}
