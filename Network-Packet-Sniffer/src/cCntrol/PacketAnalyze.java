package cCntrol;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import jpcap.packet.*;

public class PacketAnalyze {
	static Packet packet;
	static HashMap<String, String> att1, att2;
	public PacketAnalyze(Packet packet) {
		this.packet = packet;
	}
	public static HashMap<String, String> packetClass(){
		att2 = new HashMap<String, String>();
		if(packet.getClass().equals(ICMPPacket.class)) {
			att2 = ICMPanalyze();
		}
		else if(packet.getClass().equals(TCPPacket.class)) {
			att2 = TCPanalyze();
		}
		else if(packet.getClass().equals(UDPPacket.class)) {
			att2 = UDPanalyze();
		}
		return att2;
	}
	
	public static HashMap<String, String> IPanalyze(){
		att1 = new HashMap<String, String>();
		if(packet instanceof IPPacket) {
			IPPacket ippacket = (IPPacket) packet;
			att1.put("PROTOCOL", new String("IP"));//协议
			att1.put("SRC_IP", ippacket.src_ip.getHostAddress());//源IP
			att1.put("DST_IP", ippacket.dst_ip.getHostAddress());//目的IP
			att1.put("TTL", String.valueOf(ippacket.hop_limit));//最大生存时间
			att1.put("FRAGMENT: MORE FRAGMENT", String.valueOf(ippacket.more_frag));//是否还有分片
			att1.put("PRIORITY: ", String.valueOf(ippacket.priority));//优先级
			att1.put("THROUGHPUT: ", String.valueOf(ippacket.t_flag));//吞吐量
			att1.put("RELIABILITY: ", String.valueOf(ippacket.r_flag));//质量
			att1.put("LENGTH: ", String.valueOf(ippacket.length));//IP包长度
			att1.put("FRAGMENT: MORE FRAFMENT ", String.valueOf(ippacket.dont_frag));//是否能分片
			att1.put("FRAGMENT OFFSET: ", String.valueOf(ippacket.offset));//片偏移
			att1.put("IDENTIFICATION: ", String.valueOf(ippacket.ident));//标识符
			
			
		}
		return att1;
	}
	
	public static HashMap<String, String> ICMPanalyze(){
		att1 = new HashMap<String, String>();
		ICMPPacket icmppacket = (ICMPPacket) packet;
		
		att1.put("PROTOCOL", new String("ICMP"));
		att1.put("SRC_IP", icmppacket.src_ip.toString().substring(1, icmppacket.src_ip.toString().length()));
		att1.put("DST_IP", icmppacket.dst_ip.toString().substring(1, icmppacket.dst_ip.toString().length()));
		att1.put("CAPLEN: ", String.valueOf(icmppacket.caplen));
		att1.put("CODE: ", String.valueOf(icmppacket.code));//消息类型的子类型


		return att1;
	}
	
	public static HashMap<String, String> TCPanalyze(){
		att1 = new HashMap<String, String>();
		TCPPacket tcppacket = (TCPPacket) packet;
		EthernetPacket ethernetPacket = (EthernetPacket) packet.datalink;
		att1.put("PROTOCOL", new String("TCP"));//协议
		att1.put("SRC_IP", tcppacket.src_ip.toString().substring(1, tcppacket.src_ip.toString().length()));//源IP
		att1.put("DST_IP", tcppacket.dst_ip.toString().substring(1, tcppacket.dst_ip.toString().length()));//目的IP
		att1.put("S_PORT", String.valueOf(tcppacket.src_port));//源端口
		att1.put("DST_PORT", String.valueOf(tcppacket.dst_port));//目的端口
		att1.put("SRC_MAC", ethernetPacket.getSourceAddress());//源MAC地址
		att1.put("DST_MAC", ethernetPacket.getDestinationAddress());//目的MAC地址
		att1.put("CAPLEN: ", String.valueOf(tcppacket.caplen));//捕获长度
		att1.put("DATA: ", String.valueOf(tcppacket.data));//数据
		att1.put("PRIORITY: ", String.valueOf(tcppacket.priority));
		att1.put("MORE_FLAG: ", String.valueOf(tcppacket.more_frag));
		att1.put("SEQUENCE NUMBER: ", String.valueOf(tcppacket.sequence));
		att1.put("ACK_NUM: ", String.valueOf(tcppacket.ack_num));
		att1.put("ACK: ", String.valueOf(tcppacket.ack));
		att1.put("WINDOW SIZE: ", String.valueOf(tcppacket.window));
		att1.put("FIN: ", String.valueOf(tcppacket.fin));
		att1.put("SYN: ", String.valueOf(tcppacket.syn));
		att1.put("RST: ", String.valueOf(tcppacket.rst));
		att1.put("PSH: ", String.valueOf(tcppacket.psh));
	
		return att1;
	}
	
	public static HashMap<String, String> UDPanalyze(){
		att1 = new HashMap<String, String>();
		UDPPacket udppacket = (UDPPacket) packet;
		EthernetPacket ethernetPacket = (EthernetPacket) packet.datalink;
		att1.put("PROTOCOL", new String("UDP"));
		att1.put("SRC_IP", udppacket.src_ip.toString().substring(1, udppacket.src_ip.toString().length()));
		att1.put("DST_IP", udppacket.dst_ip.toString().substring(1, udppacket.dst_ip.toString().length()));
		att1.put("S_PORT", String.valueOf(udppacket.src_port));
		att1.put("DST_PORT", String.valueOf(udppacket.dst_port));
		att1.put("SRC_MAC", ethernetPacket.getSourceAddress());
		att1.put("DST_MAC", ethernetPacket.getDestinationAddress());

		att1.put("LENGTH: ", String.valueOf(udppacket.length));//长度
		att1.put("HOP_LIMIT: ", String.valueOf(udppacket.hop_limit));//最大生存时间

		return att1;
	}
}