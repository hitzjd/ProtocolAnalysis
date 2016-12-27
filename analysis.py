# -*- coding:utf-8 -*-

import struct
from AppLayerAnalyse import AppLayerAnalyse
from TransLayerAnalyse import TransLayerAnalyse


class AnalysePacket:
	def __init__(self):
		print "__init__"
		self.packet_info = {}
		self.trans_analyse = TransLayerAnalyse()
		self.app_analyse = AppLayerAnalyse()


	# 解析一个数据包信息
	def Analysis_One(self,packet):
		self.packet_info['TransLayerInfo'],app_packet = self.trans_analyse.Unpack_Tcp_Header(packet)
		self.packet_info['AppLayerInfo'] = self.app_analyse.Unpack_Iec104_Header(app_packet)

if __name__ == '__main__':
	packet = 'eb9b0964a0af2a37cd9102f85018010088a60000680407000000'
	ap = AnalysePacket() 
	app_info = ap.Analysis_One(packet)
	print ap.packet_info






