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
		pcap_header['Magic_number'] = struct.unpack('!I',packet[0:4])[0]
		pcap_header['Version_major'] = struct.unpack('H',packet[4:6])[0]
		pcap_header['Version_minor'] = struct.unpack('H',packet[6:8])[0]
		pcap_header['Thiszone'] = struct.unpack('I',packet[8:12])[0]
		pcap_header['Sigfigs'] = struct.unpack('I',packet[12:16])[0]
		pcap_header['Snaplen'] = struct.unpack('I',packet[16:20])[0]
		pcap_header['Linktype'] = struct.unpack('I',packet[20:24])[0]
		#self.packet_info['Pcapheader'] = pcap_header
		return pcap_header,packet[24:]                   #返回文件头部，文件数据部分

	# 在此将得到数据包列表
	# 。。。。

if __name__ == '__main__':
	print 'PcapAnalyse.py'