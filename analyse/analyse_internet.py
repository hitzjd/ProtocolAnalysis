#coding=utf-8
#分析网络层协议内容：Internet Protocol

import struct
import sys
sys.path.append('..')
from util.util import hex2dec

class AnalyseInternet:
	def __init__(self):
		print "__init__"
		#self.packet_info = {}
	
	#解析网络层协议
	#ipv4 header
	def unpack_ipv4_header(self,packet):
		internet_layer = {}
		internet_layer['IPversion'] = struct.unpack('B',packet[0:1])[0]  #网络层版本,首部长度
		internet_layer['IPtos'] = struct.unpack('B',packet[1:2])[0]  #服务类型
		internet_layer['IPtot_len'] = struct.unpack('H',packet[2:4])[0]  #总长度
		internet_layer['IPid'] = struct.unpack('H',packet[4:6])[0]  #标识
		internet_layer['IPflag_off'] = struct.unpack('H',packet[6:8])[0]  #标志，片偏移
		internet_layer['IPttl'] = struct.unpack('B',packet[8:9])[0]  #生存时间
		internet_layer['IPprotocol'] = struct.unpack('B',packet[9:10])[0]  #协议
		internet_layer['IPcheck'] = struct.unpack('H',packet[10:12])[0]  #头部校验和
		internet_layer['IPsaddr'] = struct.unpack('4B',packet[12:16])  #源地址
		internet_layer['IPdaddr'] = struct.unpack('4B',packet[16:20])  #目的地址
		#self.packet_info['Internetlayer'] = internet_layer
		return internet_layer,packet[20:]                   #返回IP包头，IP包数据部分
	
if __name__ == '__main__':
	print 'AnalyseInternet.py'	