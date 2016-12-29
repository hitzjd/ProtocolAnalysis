#coding=utf-8
#分析物理层层协议内容：Physical Layer

import struct
from util import hex2dec

class PhysicalAnalyse:
	def __init__(self):
		print "__init__"
		self.length
		self.packet_info = {}
	
	
	#解析物理层协议
	def Unpack_Physical_Header(self,packet):
		physicallayer = {}
		physicallayer['GMTtime'] = packet[0:4]    #时间戳
		physicallayer['MicroTime'] = packet[4:8]    #时间戳
		physicallayer['Caplen'] = packet[8:12]  #包长度
		physicallayer['Len'] = packet[12:16]    #包长度
		self.length = struct.unpack('I',pcap_packet_header['len'])[0]
		self.packet_info['Physicallayer'] = physicallayer
		return packet[16:]                   #返回物理层包数据部分

if __name__ == '__main__':
	print 'PhysicalAnalyse.py'