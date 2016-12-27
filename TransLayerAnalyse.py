# -*- coding:utf-8 -*-

from util import hex2dec

# 解析传输层协议
class TransLayerAnalyse:
	def __init__(self):
		print '__init__'

	# 解析TCP包头
	def Unpack_Tcp_Header(self,packet):
		print "unpack tcp header"
		translayer = {} #传输层信息
		translayer['Type'] = 'tcp'
		translayer['TcpSrcPort'] = hex2dec (packet[0:4])   #源端口 
		translayer['TcpDstPort'] = hex2dec (packet[4:8])   #目的端口
		translayer['TcpSeqNum'] = packet[8:16]             #序列号 
		translayer['TcpAckNum'] = packet[16:24]            #确认号 
		header_len = hex2dec (packet[24])*4            
		translayer['TcpHeaderLen'] = header_len            #tcp包头长度
		return translayer,packet[header_len*2:]          #返回TCP包头解析结果，TCP包数据部分

	# 解析UDP包头
	def Unpack_Udp_Header(self,packet):
		print "unpack udp header"
		translayer['Type'] = 'udp'
		translayer['UdpSrcPort'] = hex2dec (packet[0:4])   #源端口 
		translayer['UdpDstPort'] = hex2dec (packet[4:8])   #目的端口
		packet_len = hex2dec (packet[8:12])    
		translayer['UdpHeaderLen'] = packet_len            #udp包总长度
		return translayer,packet[16:]                    #返回UDP包头解析结果，UDP包数据部分


if __name__ == '__main__':
	print 'TransLayerAnalyse.py'
