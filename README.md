协议分析，数据包内容判断

analysis.py
    对捕包进行协议分析

util.py
    公共方法类

pcap.py
	解析pca包头部信息

AnalysePhysical.py
	解析物理层协议信息，并返回包长度
	
AnalyseEthernet.py
	解析链路层协议信息

AnalyseInternet.py
	解析网络层协议信息

TransLayerAnalyse.py
	解析传输层协议信息

AppLayerAnalyse.py
	解析应用层协议信息

进制及/x问题，暂时unpack("B",...)