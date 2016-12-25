# -*- coding:utf-8 -*-

import struct
from util import hex2dec

class AnalysePacket:
	def __init__(self):
		print "__init__"
		self.packet_info = {}

	# 解析传输层协议
	# 解析TCP包头
	def unpack_tcp_header(self,packet):
		print "unpack tcp header"
		translayer = {} #传输层信息
		translayer['type'] = 'tcp'
		translayer['src_port'] = hex2dec (packet[0:4])   #源端口 
		translayer['dst_port'] = hex2dec (packet[4:8])   #目的端口
		translayer['seq_num'] = packet[8:16]             #序列号 
		translayer['ack_num'] = packet[16:24]            #确认号 
		header_len = hex2dec (packet[24])*4            
		translayer['header_len'] = header_len            #tcp包头长度
		self.packet_info['translayer'] = translayer
		return packet[header_len*2:]                   #返回TCP包数据部分

	# 解析UDP包头
	def unpack_udp_header(self,packet):
		print "unpack udp header"
		translayer['type'] = 'udp'
		translayer['src_port'] = hex2dec (packet[0:4])   #源端口 
		translayer['dst_port'] = hex2dec (packet[4:8])   #目的端口
		packet_len = hex2dec (packet[8:12])    
		translayer['packet_len'] = packet_len            #udp包总长度
		self.packet_info['translayer'] = translayer
		return packet[16:]                             #返回UDP包数据部分


	# 解析应用层协议
	# 解析IEC104协议
	def unpack_iec104_header(self,packet):
		print "unpack iec104 header"
		if not hex2dec (packet[0:2]) == 104:
			print "not iec104"
		applayer = {}
		applayer['type'] = 'iec104'
		packet_len = hex2dec (packet[2:4])
		applayer['packet_len'] = packet_len          #apci和asdu的总长度
		applayer['apci'] = packet[4:12]              #控制部分，可以用来判断包的类型（I/S/U）
		applayer['asdu'] = packet[12:]               #数据部分，存储指令信息
		self.packet_info['applayer'] = applayer

if __name__ == '__main__':
	packet = 'eb9b0964a0af2a37cd9102f85018010088a60000680407000000'
	ap = AnalysePacket() 
	app_info = ap.unpack_tcp_header(packet)
	ap.unpack_iec104_header(app_info)
	print ap.packet_info






