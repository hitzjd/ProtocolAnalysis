#coding=utf-8
#分析pcap文件内容

import struct
import sys
sys.path.append('..')
from util.util import hex2dec

class AnalysePcap:
	def __init__(self):
		print "__init__"
		#self.packet_info = {}
	
	#pcap文件包头解析
	def unpack_pcap_header(self,packet):
		pcap_header = {}
		pcap_header['Magic_number'] = packet[0:4]
		pcap_header['Version_major'] = packet[4:6]
		pcap_header['Version_minor'] = packet[6:8]
		pcap_header['Thiszone'] = packet[8:12]
		pcap_header['Sigfigs'] = packet[12:16]
		pcap_header['Snaplen'] = packet[16:20]
		pcap_header['Linktype'] = packet[20:24]
		#self.packet_info['Pcapheader'] = pcap_header
		return pcap_header,packet[24:]                   #返回文件头部，文件数据部分

	# 在此将得到数据包列表
	# 。。。。

if __name__ == '__main__':
	print 'PcapAnalyse.py'