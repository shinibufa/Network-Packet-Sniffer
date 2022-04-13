package cCntrol;

import java.io.IOException;
import java.text.*;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;
import jpcap.*;
import jpcap.packet.*;


public class PacketCapture implements Runnable {
	NetworkInterface device;
	static DefaultTableModel tab_mod;
	static String FilterMsg = "";
	static ArrayList<Packet> packetlist = new ArrayList<Packet>();
	public PacketCapture() {

	}
	
	public void SetDevice(NetworkInterface device) {
		this.device = device;
	}
	
	public void SetTable(DefaultTableModel tab_mod) {
		PacketCapture.tab_mod = tab_mod;
	}
	
	public void SetFilter(String FilterMsg) {
		PacketCapture.FilterMsg = FilterMsg;
		System.out.println(FilterMsg);
	}
	
	public void ClearPackets() {
		packetlist.clear();

	}
	@Override
	public void run() {

		Packet packet;
		try {
			//int i = 500;
			JpcapCaptor captor = JpcapCaptor.openDevice(device, 65535, true, 20);
			while(true) {
				//i--;
				long StartTime = System.currentTimeMillis();
				while(StartTime + 1000 >= System.currentTimeMillis()) {
					
					packet = captor.getPacket();

					if(packet != null && Filter(packet, PacketCapture.FilterMsg)) {
						packetlist.add(packet);
						ShowTable(packet);
					}
				}
				Thread.sleep(2500);
			} 
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	public static void ShowTable(Packet packet) {
		String[] rowData = GetObj(packet);
		tab_mod.addRow(rowData);
	}
	
	public static ArrayList<Packet> GetPacketList(){
		return packetlist;
	}
	
	public static boolean Filter(Packet packet, String FilterMsg) {
		//根据协议进行抓包
		switch(FilterMsg) {
		case "TCP":
			new PacketAnalyze(packet);
			if(PacketAnalyze.packetClass().get("PROTOCOL").equals("TCP")) {
				return true;
			}
			break;
		case "ICMP":
			new PacketAnalyze(packet);
			if(PacketAnalyze.packetClass().get("PROTOCOL").equals("ICMP")) {
				return true;
			}
		case "UDP":
			new PacketAnalyze(packet);
			if(PacketAnalyze.packetClass().get("PROTOCOL").equals("UDP")) {
				return true;
			}
			
		}
		

		if(FilterMsg.contains("SRC_IP")) {
			String SRC_IP = FilterMsg.substring(7, FilterMsg.length());
			new PacketAnalyze(packet);
			if(PacketAnalyze.packetClass().get("SRC_IP").equals(SRC_IP)) {
				return true;
				}

			}
			else if(FilterMsg.contains("DST_IP")) {
			String DST_IP = FilterMsg.substring(7, FilterMsg.length());			
			new PacketAnalyze(packet);
			if(PacketAnalyze.packetClass().get("DST_IP").equals(DST_IP)) {
				return true;
				}
			}
			else if(FilterMsg == "ICMP"){
				new PacketAnalyze(packet);
				if(PacketAnalyze.packetClass().get("PROTOCOL").equals("ICMP")){
					return true;
				}
			}
			else if(FilterMsg == "UDP"){
				new PacketAnalyze(packet);
				if(PacketAnalyze.packetClass().get("PROTOCOL").equals("UDP")){
					return true;
				}
			}else if(FilterMsg == "TCP"){
				new PacketAnalyze(packet);
				if(PacketAnalyze.packetClass().get("PROTOCL").equals("TCP")){
					return true;
				}
			}
			else if(FilterMsg.contains("KeyWord")) {
				String KeyWord = FilterMsg.substring(8, FilterMsg.length());
				new PacketAnalyze(packet);
				if(PacketAnalyze.packetClass().get("DATA").contains(KeyWord)) {

					return true;
				}
			}
			else if(FilterMsg.equals("")){
				return true;
			}
			return false;
	}
	

	public static String[] GetObj(Packet packet) {
		String[] data = new String[6];
		new PacketAnalyze(packet);
		if(packet != null && PacketAnalyze.packetClass().size() >= 3 ) {

			
			Date date = new Date();
			DateFormat df= new SimpleDateFormat("HH:mm:ss");
			
			data[0] = df.format(date);
			new PacketAnalyze(packet);
			data[1] = PacketAnalyze.packetClass().get("SRC_IP");
			data[2] = PacketAnalyze.packetClass().get("DST_IP");
			data[3] = PacketAnalyze.packetClass().get("PROTOCOL");
			data[4] = String.valueOf(packet.len);

		}
		return data;
	}


}