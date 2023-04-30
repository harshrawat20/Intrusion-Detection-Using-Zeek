# This script detects potential Denial of Service (DoS) attacks
module SYNFLOOD;

# Define the thresholds for each indicator
const SYN_THRESHOLD: count = 50;


redef enum Notice::Type += {
    SYNFlood
};



function generate_syn_notice(c: connection, pkt: SYN_packet) {

    if(pkt$size> SYN_THRESHOLD){
   	NOTICE([$note = SYNFlood,
            $msg = fmt("Potential SYN flood detected from %s to %s", c$id$orig_h, c$id$resp_h),
            $conn = c,
            $uid = c$uid
        ]);
   	}

}

event connection_SYN_packet(c: connection, pkt: SYN_packet){
	generate_syn_notice(c, pkt);
   
   	}
   	
