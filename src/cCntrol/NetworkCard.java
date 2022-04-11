package cCntrol;
import jpcap.*;

/*获取网卡列表*/
public class NetworkCard{
	String[] devices;
	public static NetworkInterface[] getDevices() {
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		return devices;
	}
}