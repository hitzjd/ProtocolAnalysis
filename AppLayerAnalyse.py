# -*- coding:utf-8 -*-

from util import hex2dec

# 解析应用层协议
class AppLayerAnalyse:
	def __init__(self):
		print '__init__'

	# 解析IEC104协议
	def UnpackIec104Header(self,packet):
		print "unpack iec104 header"
		if not hex2dec (packet[0:2]) == 104:
			print "not iec104"
		applayer = {}
		applayer['Type'] = 'iec104'
		packet_len = hex2dec (packet[2:4])
		applayer['IecPacketLen'] = packet_len          #apci和asdu的总长度
		applayer['IecApci'] = packet[4:12]              #控制部分，可以用来判断包的类型（I/S/U）
		applayer['IecAsdu'] = packet[12:]               #数据部分，存储指令信息
		return applayer

if __name__ == '__main__':
	print 'AppLayerAnalyse.py'