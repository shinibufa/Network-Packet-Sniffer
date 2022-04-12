package show;

import java.awt.*;
import java.awt.event.*;
import java.io.FileOutputStream;
import java.util.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import jpcap.NetworkInterface;
import jpcap.packet.Packet;

import cCntrol.PacketCapture;
import cCntrol.NetworkCard;
import cCntrol.PacketAnalyze;


public class MyInterface extends JFrame{
	JMenuBar menubar;
	JMenu menuFile1, menuFile2;
	JMenuItem[] jitem;
	JMenuItem protocol1, protocol2, protocol3;
	JTextField searchText;
	JButton SIPBut, DIPBut, searchBut;
	JPanel panle;
	JScrollPane scrollPane;
	JTable table;
	final String[] head = new String[] {
			"TIME", "SRC_IP", "DST_IP", "PROTOCOL", "LENGTH"
	};
	NetworkInterface[] devices;
	Object[][] datalist = {};
	DefaultTableModel tableModel;
	PacketCapture allpackets;
	public MyInterface() {


		allpackets = new PacketCapture();
		setVisible(true);
		this.setTitle("JSniffer");
		this.setBounds(300, 400, 500, 500);
		menubar = new JMenuBar();
		menuFile1= new JMenu("Net_Card");
		NetworkInterface[] devices = new NetworkCard().getDevices();
		for(NetworkInterface n : devices) {
			System.out.println(n.name +"|" + n.description);
		}

		jitem = new JMenuItem[devices.length];
		for(int i = 0; i < devices.length; i++) {
			jitem[i] = new JMenuItem(i + ": " + devices[i].name + "(" + devices[i].description + ")");
			menuFile1.add(jitem[i]);
			jitem[i].addActionListener(new CardActionListener(devices[i]));
		}
		
		menuFile2 = new JMenu("PROTOCOL");
		protocol1 = new JMenu("ICMP");
		protocol2 = new JMenu("TCP");
		protocol3 = new JMenu("UDP");

		protocol1.addActionListener(
				new ActionListener() {
					public void actionPerformed(ActionEvent e3) {
						allpackets.SetFilter("ICMP");
						allpackets.ClearPackets();
						while(tableModel.getRowCount() > 0) {
							tableModel.removeRow(tableModel.getRowCount() - 1);
						}
					}
				}
				);
		protocol2.addActionListener(
				new ActionListener() {
					public void actionPerformed(ActionEvent e3) {
						allpackets.SetFilter("TCP");
						allpackets.ClearPackets();
						while(tableModel.getRowCount() > 0) {
							tableModel.removeRow(tableModel.getRowCount() - 1);
						}
					}
				}
				);
		protocol3.addActionListener(
				new ActionListener() {
					public void actionPerformed(ActionEvent e3) {
						allpackets.SetFilter("UDP");
						allpackets.ClearPackets();
						while(tableModel.getRowCount() > 0) {
							tableModel.removeRow(tableModel.getRowCount() - 1);
						}
					}
				}
				);
		menuFile2.add(protocol1);
		menuFile2.add(protocol2);
		menuFile2.add(protocol3);
		
		SIPBut = new JButton("SRC_IP");
		DIPBut = new JButton("DST_IP");
		searchBut = new JButton("search");

//		Mymonitor1 mymonitor1 = new Mymonitor1();
//		Mymonitor2 mymonitor2 = new Mymonitor2();
//		Mymonitor3 mymonitor3 = new Mymonitor3();
//		SIPBut.addActionListener(mymonitor1);
//		DIPBut.addActionListener(mymonitor2);
//		searchBut.addActionListener(mymonitor3);
//		
//		final class Mymonitor1 implements ActionListener{
//			@Override
//			public void actionPerformed(ActionEvent e) {
//				String SIP_S = JOptionPane.showInputDialog("Please input SOURCE IP");
//				allpackets.SetFilter("SRC_IP" + SIP_S);
//				allpackets.ClearPackets();
//				while(tableMode.getRowCount() > 0) {
//					tableModel.removeRow(tableModel.getRowCount() - 1);
//				}
//			}
//		}
//		
//		final class Mymonitor2 implements ActionListener{
//			@Override
//			public void actionPerformed(ActionEvent e) {
//				String DIP_S = JOptionPane.showInputDialog("Please input DSTINATION IP");
//				allpackets.SetFilter("DST_IP" + DIP_S);
//				allpackets.ClearPackets();
//				while(tableMode.getRowCount() > 0) {
//					tableModel.removeRow(tableModel.getRowCount() - 1);
//				}
//			}
//		}
//		
//		final class Mymonitor3 implements ActionListener{
//			@Override
//			public void actionPerformed(ActionEvent e) {
//				String KEY_S = JOptionPane.showInputDialog("Please input KEYWORD");
//				allpackets.SetFilter("KEYWORD" + KEY_S);
//				allpackets.ClearPackets();
//				while(tableMode.getRowCount() > 0) {
//					tableModel.removeRow(tableModel.getRowCount() - 1);
//				}
//			}
//		}
		
		SIPBut.addActionListener(
				new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						String SIP_S = JOptionPane.showInputDialog("Please input SOURCE IP");
						allpackets.SetFilter("SRC_IP" + SIP_S);
						allpackets.ClearPackets();
						while(tableModel.getRowCount() > 0) {
							tableModel.removeRow(tableModel.getRowCount() - 1);
						}
					}
				}
				);
		System.out.println("sahjasd");
		
		DIPBut.addActionListener(
				new ActionListener() {
					public void actionPerformed(ActionEvent e) {
					String DIP_S = JOptionPane.showInputDialog("Please input DSTINATION IP");
					allpackets.SetFilter("DST_IP" + DIP_S);
					allpackets.ClearPackets();
					while(tableModel.getRowCount() > 0) {
						tableModel.removeRow(tableModel.getRowCount() - 1);
					}
				}
				}
				);
		
		searchBut.addActionListener(
				new ActionListener() {
					public void actionPerformed(ActionEvent e) {
					String KEY_S = JOptionPane.showInputDialog("Please input KEYWORD");
					allpackets.SetFilter("KEYWORD" + KEY_S);
					allpackets.ClearPackets();
					while(tableModel.getRowCount() > 0) {
						tableModel.removeRow(tableModel.getRowCount() - 1);
					}
				}
				}
				);
		
		menubar.add(menuFile1);
		menubar.add(menuFile2);
		menubar.add(SIPBut);
		menubar.add(DIPBut);
		menubar.add(searchBut);
		setJMenuBar(menubar);
		
		tableModel = new DefaultTableModel(datalist, head);
		table = new JTable(tableModel) {
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		
		allpackets.SetTable(tableModel);
		table.setPreferredScrollableViewportSize(new Dimension(400,50));
		table.setRowHeight(20);
		table.setRowMargin(5);
		table.setRowSelectionAllowed(true);
		table.setSelectionBackground(Color.gray);
		table.setSelectionForeground(Color.BLACK);
		table.setShowGrid(true);
		table.doLayout();
		scrollPane = new JScrollPane(table);
		JPanel panel = new JPanel(new GridLayout(0, 1));
		panel.setPreferredSize(new Dimension(500, 200));
		panel.setBackground(Color.cyan);
		panel.add(scrollPane);
		setContentPane(panel);
		pack();
		
		table.addMouseListener(new MouseAdapter() {
			public void mouseClicked(MouseEvent e) {
				if(e.getClickCount() == 2) {
					int row = table.getSelectedRow();
					JFrame frame = new JFrame("details");
					JPanel panel = new JPanel();
					final JTextArea inf = new JTextArea(20, 40);
					inf.setEditable(false);
					inf.setLineWrap(true);
					inf.setWrapStyleWord(true);
					frame.add(panel);
					panel.add(new JScrollPane(inf));
					JButton Save_Button = new JButton("save");
					Save_Button.addActionListener(
							new ActionListener() {
								public void actionPerformed(ActionEvent e) {
									String text = inf.getText();
									int filename = (int)System.currentTimeMillis();
									try {
										FileOutputStream fos = new FileOutputStream("d://"+ filename + ".txt");
										fos.write(text.getBytes());
										fos.close();
									} catch (Exception e1) {
										e1.printStackTrace();
									}
								}
								
								
							}
							);
					panel.add(Save_Button);
					frame.setBounds(100, 100, 400, 400);
					frame.setVisible(true);
					frame.setResizable(true);
					ArrayList<Packet> packetlist = allpackets.GetPacketList();
					Map<String, String> hm1 = new HashMap<String, String>();
					Map<String, String> hm2 = new HashMap<String, String>();
					Packet packet = packetlist.get(row);
					inf.append("---------the information of IP header----------");
					hm1 = new PacketAnalyze(packet).IPanalyze();
					for(Map.Entry<String, String> entry1 : hm1.entrySet()) {
						inf.append(entry1.getKey()+ " : " + entry1.getValue() + "\n");
						
					}
					hm2 = new PacketAnalyze(packet).packetClass();
					inf.append("--------"+hm2.get("PROTOCL")+"the information of header:--------");
					for(Map.Entry<String, String> entry2 : hm2.entrySet()) {
						inf.append(entry2.getKey() + " : " + entry2.getValue());
					}
				}
			}
		});
		setResizable(true);
		addWindowListener(new WindowAdapter() {
			public void winodwClosing(WindowEvent e) {
				System.exit(0);
			}
		}
				);
	}

	private class CardActionListener implements ActionListener{
		NetworkInterface device;
		CardActionListener(NetworkInterface device){
			this.device = device;
		}
		public void actionPerformed(ActionEvent e) {
			setTitle("Jsniffer: " + device.name);
			allpackets.SetDevice(device);
			allpackets.SetFilter("");
			new Thread(allpackets).start();
		}
	}

}