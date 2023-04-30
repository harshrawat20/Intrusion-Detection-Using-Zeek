event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	# Log hw address for client matching IP.
	if ( msg$ciaddr == 172.17.1.129 ){
		print msg$chaddr;
		print options$host_name;
		}
	}

