协议分析，数据包内容判断

analysis.py
    对捕包进行协议分析

util包
	公共方法类包

	-- util.py
    	公共方法类


analyse包
	分析代码包

	-- analyse_pcap.py
		解析pcap文件信息

	-- analyse_physical.py
		解析原始数据包，得到时间戳，总包长信息

	-- analyse_ethernet.py
		解析链路层协议信息

	-- analyse_internet.py
		解析网络层协议信息

	-- analyse_transport.py
		解析传输层协议信息

	-- analyse_application.py
		解析应用层协议信息


未明确问题：
	进制及/x问题，暂时unpack("B",...)