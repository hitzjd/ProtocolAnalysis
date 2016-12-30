#coding=utf-8
#分析链路层协议内容：Ethernet

import struct
import sys
sys.path.append('..')
from util.util import hex2dec

class AnalyseEthernet:
	def __init__(self):
		print "__init__"
		#self.packet_info = {}
	
	#解析链路层协议
	def unpack_ethernet_header(self,packet):
		ethernetlayer = {}
		ethernetlayer['SrcMac'] = packet[0:6] #源Mac
		ethernetlayer['DesMac'] = packet[6:12] #目的Mac
		ethernetlayer['Ethernettype'] = packet[12:14]   #链路层协议类型
		#self.packet_info['Ethernetlayer'] = ethernetlayer
		return ethernetlayer,packet[14:]                   #返回链路层包头，链路层包数据部分

if __name__ == '__main__':
	print 'AnalyseEthernet.py'