# This script detects potential Denial of Service (DoS) attacks
module HTTPDOS;

# Define the thresholds for each indicator
const HTTP_THRESHOLD: count = 100;



redef enum Notice::Type += {
    HTTPDos
};




function generate_http_dos_notice(c: connection, stats: http_stats_rec) {

    if(stats$num_requests > HTTP_THRESHOLD){
   	NOTICE([$note = HTTPDos,
            $msg = fmt("Potential HTTP DOS detected from %s to %s", c$id$orig_h, c$id$resp_h),
            $conn = c,
            $uid = c$uid
        ]);
   	}

}

event http_stats(c: connection, stats: http_stats_rec) {
  # Check for an HTTP flood attack
  generate_http_dos_notice(c, stats);

}

