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
			att1.put("PROTOCOL", new String("IP"));
			att1.put("SRC_IP", ippacket.src_ip.toString().substring(1, ippacket.src_ip.toString().length()));
			att1.put("DST_IP", ippacket.dst_ip.toString().substring(1, ippacket.dst_ip.toString().length()));
			att1.put("TTL", String.valueOf(ippacket.hop_limit));
			att1.put("HEADER_LEN", String.valueOf(ippacket.header.length));
			att1.put("MORE_FLAG", String.valueOf(ippacket.more_frag));
		}
		return att1;
	}
	
	public static HashMap<String, String> ICMPanalyze(){
		att1 = new HashMap<String, String>();
		ICMPPacket icmppacket = (ICMPPacket) packet;
		
		att1.put("PROTOCOL", new String("ICMP"));
		att1.put("SRC_IP", icmppacket.src_ip.toString().substring(1, icmppacket.src_ip.toString().length()));
		att1.put("DST_IP", icmppacket.dst_ip.toString().substring(1, icmppacket.dst_ip.toString().length()));

		return att1;
	}
	
	public static HashMap<String, String> TCPanalyze(){
		att1 = new HashMap<String, String>();
		TCPPacket tcppacket = (TCPPacket) packet;
		EthernetPacket ethernetPacket = (EthernetPacket) packet.datalink;
		att1.put("PROTOCOL", new String("TCP"));
		att1.put("SRC_IP", tcppacket.src_ip.toString().substring(1, tcppacket.src_ip.toString().length()));
		att1.put("DST_IP", tcppacket.dst_ip.toString().substring(1, tcppacket.dst_ip.toString().length()));
		att1.put("S_PORT", String.valueOf(tcppacket.src_port));
		att1.put("DST_PORT", String.valueOf(tcppacket.dst_port));
		att1.put("SRC_MAC", ethernetPacket.getSourceAddress());
		att1.put("DST_MAC", ethernetPacket.getDestinationAddress());
		
		return att1;
	}
	
	public static HashMap<String, String> UDPanalyze(){
		att1 = new HashMap<String, String>();
		UDPPacket udppacket = (UDPPacket) packet;
		EthernetPacket ethernetPacket = (EthernetPacket) packet.datalink;
		att1.put("PROTOCOL", new String("TCP"));
		att1.put("SRC_IP", udppacket.src_ip.toString().substring(1, udppacket.src_ip.toString().length()));
		att1.put("DST_IP", udppacket.dst_ip.toString().substring(1, udppacket.dst_ip.toString().length()));
		att1.put("S_PORT", String.valueOf(udppacket.src_port));
		att1.put("DST_PORT", String.valueOf(udppacket.dst_port));
		att1.put("SRC_MAC", ethernetPacket.getSourceAddress());
		att1.put("DST_MAC", ethernetPacket.getDestinationAddress());
		try {
			att1.put("DATA", new String(udppacket.data,"GBK"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		return att1;
	}
}