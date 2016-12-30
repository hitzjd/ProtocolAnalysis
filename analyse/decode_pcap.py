#coding=utf-8
#分析pcap文件内容

import struct
from util import hex2dec

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
	
	def unpack_physical_header(self,packet):
		physical_layer = {}
		physical_layer['GMTtime'] = packet[0:4]    #时间戳
		physical_layer['MicroTime'] = packet[4:8]    #时间戳
		physical_layer['Caplen'] = packet[8:12]  #包长度
		physical_layer['Len'] = packet[12:16]    #包长度
		packet_length = packet[12]+packet[13]*256+packet[14]*256*256+packet[15]*256*256*256	#对应于修改输入转化为一字节的无符号数
		#packet_length = struct.unpack('I',physicallayer['Len'])[0]
		#print physicallayer['Len'],packet_length
		#self.length = struct.unpack('I',physical_layer['Len'])[0]
		#self.packet_info['Physicallayer'] = physical_layer
		return physical_layer,packet[16:packetlength],packet[16+packetlength:],packet_length                   #返回物理层包头，物理层包数据部分,剩余文件内容,包长
	

if __name__ == '__main__':
	print 'Analysepcap.py'	