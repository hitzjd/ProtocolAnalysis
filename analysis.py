# -*- coding:utf-8 -*-

import struct
from analyse.analyse_pcap import AnalysePcap
from analyse.analyse_physical import AnalysePhysical
from analyse.analyse_ethernet import AnalyseEthernet
from analyse.analyse_internet import AnalyseInternet
from analyse.analyse_application import AnalyseApplication
from analyse.analyse_transport import AnalyseTransport


class AnalysePacket:
	def __init__(self):
		print "__init__"
		self.packet_info = {}
		self.__analyse_ethernet = AnalyseEthernet()
		self.__analyse_ip = AnalyseInternet()		
		self.__analyse_trans = AnalyseTransport()
		self.__analyse_app = AnalyseApplication()

	# 分析pcap文件，返回所有数据包信息
	def analyse_pcap(self,filename):
		print 'Analyse_Pcap'

	def analyse_all(self,packets):
		print 'Analyse_All'
		# 得到所有包组成的列表
		# 。。。。。

		# 遍历所有的包
		# while 
		# 。。。。。

	# 解析一个数据包信息
	def analysis_one(self,packet):
		self.packet_info['EthernetlayerInfo'],ip_packet = self.__analyse_ethernet.unpack_ethernet_header(packet)
		self.packet_info['IPlayerInfo'],trans_packet = self.__analyse_ip.unpack_ipv4_header(ip_packet)
		#self.packet_info['TransLayerInfo'],app_packet = self.__analyse_trans.unpack_tcp_header(trans_packet)
		#self.packet_info['AppLayerInfo'] = self.__analyse_app.unpack_iec104_header(app_packet)

if __name__ == '__main__':
	fpcap = open('pcap_file/target.cap','rb')
	string_data = fpcap.read()[0:100]
	n = len(string_data)
	print string_data
	# print string_data[0:4]
	# print repr(string_data)[0:100]
	# print struct.unpack('13178979B',string_data)
	# string_data = struct.unpack('13178979B',string_data) 	#修改，试图读入转换为一字节的无符号数，但这里需要输入具体数字，需修改
	
	pcap_header,string_data = AnalysePcap().unpack_pcap_header(string_data)
	physical_header,this_string_data,string_data,length = AnalysePhysical().unpack_physical_header(string_data)
	ethernet_header,this_string_data = AnalyseEthernet().unpack_ethernet_header(this_string_data)
	ipv4_header,this_string_data = AnalyseInternet().unpack_ipv4_header(this_string_data)
	print pcap_header,'\n',physical_header,'\n',ethernet_header,'\n',ipv4_header,'\n',this_string_data
	#print n

	'''
	#pcap文件的数据包解析
	i =24 #pcap文件头24字节	
	while (i<n):
		physicallayer,packet,string_data,packetlength = AnalysePhysical().unpack_physical_header(string_data)
		#packet = 'eb9b0964a0af2a37cd9102f85018010088a60000680407000000'
		ap = AnalysePacket() 
		app_info = ap.analysis_one(packet)
		print ap.packet_info
		#print i,packetlength,len(packet)
		i = i+ packetlength+16
		
	'''
		
	fpcap.close()
