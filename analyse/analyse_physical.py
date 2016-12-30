#coding=utf-8
#分析物理层层协议内容：Physical Layer

import struct
import sys
sys.path.append('..')
from util.util import hex2dec

class AnalysePhysical:
	def __init__(self):
		print "__init__"
		#self.length
		#self.packet_info = {}
	
	#解析物理层协议
	def unpack_physical_header(self,packet):
		physical_layer = {}
		physical_layer['GMTtime'] = packet[0:4]    #时间戳
		physical_layer['MicroTime'] = packet[4:8]    #时间戳
		physical_layer['Caplen'] = packet[8:12]  #包长度
		physical_layer['Len'] = packet[12:16]    #包长度
		packet_length = packet[12]+packet[13]*256+packet[14]*256*256+packet[15]*256*256*256	#对应于修改输入转化为一字节的无符号数
		#packetlength = struct.unpack('I',physicallayer['Len'])[0]
		#print physicallayer['Len'],packetlength
		#self.length = struct.unpack('I',physicallayer['Len'])[0]
		#self.packet_info['Physicallayer'] = physicallayer
		return physical_layer,packet[16:packetlength],packet[16+packetlength:],packet_length                   #返回物理层包头，物理层包数据部分,剩余文件内容,包长
	
if __name__ == '__main__':
	print 'Analysephysical.py'