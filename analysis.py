# -*- coding:utf-8 -*-

import struct
from pcap import AnalysePcap
from AnalysePhysical import AnalysePhysical
from AnalyseEthernet import AnalyseEthernet
from AnalyseInternet import AnalyseInternet
from AppLayerAnalyse import AppLayerAnalyse
from TransLayerAnalyse import TransLayerAnalyse


class AnalysePacket:
	def __init__(self):
		print "__init__"
		self.packet_info = {}
		self.ethernet_analyse = AnalyseEthernet()
		self.ip_analyse = AnalyseInternet()		
		self.trans_analyse = TransLayerAnalyse()
		self.app_analyse = AppLayerAnalyse()


	# 解析一个数据包信息
	def AnalysisOne(self,packet):
		self.packet_info['EthernetlayerInfo'],ip_packet = self.ethernet_analyse.Unpack_ethernet_header(packet)
		self.packet_info['IPlayerInfo'],trans_packet = self.ip_analyse.Unpack_ipv4_header(ip_packet)
		#self.packet_info['TransLayerInfo'],app_packet = self.trans_analyse.UnpackTcpHeader(trans_packet)
		#self.packet_info['AppLayerInfo'] = self.app_analyse.UnpackIec104Header(app_packet)

if __name__ == '__main__':
	fpcap = open('target.cap','rb')
	string_data = fpcap.read()
	n = len(string_data)
	#print repr(string_data)
	print struct.unpack('13178979B',string_data)
	#string_data = struct.unpack('13178979B',string_data) 	#修改，试图读入转换为一字节的无符号数，但这里需要输入具体数字，需修改
	
	pcap_header,string_data = AnalysePcap().Unpack_pcap_header(string_data)
	#print n
	#pcap文件的数据包解析
	i =24 #pcap文件头24字节	
	while (i<n):
		physicallayer,packet,string_data,packetlength = AnalysePhysical().Unpack_physical_header(string_data)
		#packet = 'eb9b0964a0af2a37cd9102f85018010088a60000680407000000'
		ap = AnalysePacket() 
		app_info = ap.AnalysisOne(packet)
		print ap.packet_info
		#print i,packetlength,len(packet)
		i = i+ packetlength+16
		
		
	fpcap.close()
