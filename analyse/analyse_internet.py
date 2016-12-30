#coding=utf-8
#分析网络层协议内容：Internet Protocol

import struct
from util import hex2dec

class AnalyseInternet:
	def __init__(self):
		print "__init__"
		#self.packet_info = {}
	
	#解析网络层协议
	#ipv4 header
	def unpack_ipv4_header(self,packet):
		internet_layer = {}
		internet_layer['IPversion'] = packet[0:1]  #网络层版本,首部长度
		internet_layer['IPtos'] = packet[1:2]  #服务类型
		internet_layer['IPtot_len'] = packet[2:4]  #总长度
		internet_layer['IPid'] = packet[4:6]  #标识
		internet_layer['IPflag_off'] = packet[6:8]  #标志，片偏移
		internet_layer['IPttl'] = packet[8:9]  #生存时间
		internet_layer['IPprotocol'] = packet[9:10]  #协议
		internet_layer['IPcheck'] = packet[10:12]  #头部校验和
		internet_layer['IPsaddr'] = packet[12:16]  #源地址
		internet_layer['IPdaddr'] = packet[16:20]  #目的地址
		#self.packet_info['Internetlayer'] = internet_layer
		return internet_layer,packet[20:]                   #返回IP包头，IP包数据部分
	
if __name__ == '__main__':
	print 'analyseinternet.py'	