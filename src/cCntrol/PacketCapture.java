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
		System.out.println("xigouPC");
	}
	
	public void SetDevice(NetworkInterface device) {
		this.device = device;
	}
	
	public void SetTable(DefaultTableModel tab_mod) {
		this.tab_mod = tab_mod;
	}
	
	public void SetFilter(String FilterMsg) {
		this.FilterMsg = FilterMsg;
	}
	
	public void ClearPackets() {
		packetlist.clear();
	}
	@Override
	public void run() {
		Packet packet;
		try {
			int i = 10;
			JpcapCaptor captor = JpcapCaptor.openDevice(device, 65535, true, 50);
			while(i>0) {
				i--;
				long StartTime = System.currentTimeMillis();
				while(StartTime + 1000 >= System.currentTimeMillis()) {
					
					packet = captor.getPacket();
					if(packet != null && TestFilter(packet)) {
						//System.out.println(packet);
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
	
	public static boolean TestFilter(Packet packet) {
		if(FilterMsg.contains("SRC_IP")) {
			String SRC_IP = FilterMsg.substring(4, FilterMsg.length());
			if(new PacketAnalyze(packet).packetClass().get("SRC_IP").equals(SRC_IP)) {
				return true;
				}

			}
			else if(FilterMsg.contains("DST_IP")) {
			String DST_IP = FilterMsg.substring(4, FilterMsg.length());			
			if(new PacketAnalyze(packet).packetClass().get("DST_IP").equals(DST_IP)) {
				return true;
				}
			}
			else if(FilterMsg.contains("ICMP")) {
				if(new PacketAnalyze(packet).packetClass().get("PROTOCOL").equals("ICMP")) {
					return true;
				}
		
			}
			else if(FilterMsg.contains("UDP")) {
				if(new PacketAnalyze(packet).packetClass().get("PROTOCOL").equals("UDP")) {
					return true;
				}
			}
			else if(FilterMsg.contains("TCP")) {
				if(new PacketAnalyze(packet).packetClass().get("PROTOCOL").equals("TCP")) {
					return true;
				}
			}
			else if(FilterMsg.contains("KeyWord")) {
				String KeyWord = FilterMsg.substring(8, FilterMsg.length());
				if(new PacketAnalyze(packet).packetClass().get("DATA").contains(KeyWord)) {
					return true;
				}
			}
			else if(FilterMsg.equals("")){
				return true;
			}
		return false;
	}
	
	//将抓包信息显示在列表上,以String列表形式返回信息
	public static String[] GetObj(Packet packet) {
		String[] data = new String[5];
		if(packet != null && new PacketAnalyze(packet).packetClass().size() >=3 ) {
			Date date = new Date();
			DateFormat df= new SimpleDateFormat("HH:mm:ss");
			data[0] = df.format(date);
			data[1] = new PacketAnalyze(packet).packetClass().get("SRC_IP");
			data[2] = new PacketAnalyze(packet).packetClass().get("DST_IP");
			data[3] = new PacketAnalyze(packet).packetClass().get("PROTOCOL");
			data[4] = String.valueOf(packet.len);
		}
		return data;
	}


}