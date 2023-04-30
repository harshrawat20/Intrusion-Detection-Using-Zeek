event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	# Log hw address for client matching IP.
	if ( msg$ciaddr == 192.168.2.147 ){
		print msg$chaddr;
		print options$host_name;
		}
	}

