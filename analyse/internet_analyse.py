#coding=utf-8
#分析网络层协议内容：Internet Protocol

import struct
import sys
sys.path.append('..')
from util.util import hex2dec

class InternetAnalyse:
	def __init__(self):
		print "__init__"
		#self.packet_info = {}
	
	#解析网络层协议
	#ipv4 header
	def unpack_ipv4_header(self,packet):
		internetlayer = {}
		internetlayer['IPversion'] = packet[0:1]  #网络层版本,首部长度
		internetlayer['IPtos'] = packet[1:2]  #服务类型
		internetlayer['IPtot_len'] = packet[2:4]  #总长度
		internetlayer['IPid'] = packet[4:6]  #标识
		internetlayer['IPflag_off'] = packet[6:8]  #标志，片偏移
		internetlayer['IPttl'] = packet[8:9]  #生存时间
		internetlayer['IPprotocol'] = packet[9:10]  #协议
		internetlayer['IPcheck'] = packet[10:12]  #头部校验和
		internetlayer['IPsaddr'] = packet[12:16]  #源地址
		internetlayer['IPdaddr'] = packet[16:20]  #目的地址
		#self.packet_info['Internetlayer'] = internetlayer
		return internetlayer,packet[20:]                   #返回IP包头，IP包数据部分
	
if __name__ == '__main__':
	print 'AnalyseInternet.py'	