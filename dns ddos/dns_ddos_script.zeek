module DDosAttacks;

redef enum Notice::Type += {
    DNSDDoSAmplification
};

function generate_ddos_notice(c: connection, query: string) {

    local query1: string = strip(query);
    if (query1 == "peacecorps.gov" || query1 == "pizzaseo.com") {
        NOTICE([$note = DNSDDoSAmplification,
            $msg = fmt("Possible DNS DDoS Amplification Attack"),
            $conn = c,
            $uid = c$uid
        ]);
        
    }
    else{
    NOTICE([$note = DNSDDoSAmplification,
            $msg = fmt("Not a DNS DDoS Amplification Attack"),
            $conn = c,
            $uid = c$uid
        ]);
        
    }

}
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {

    generate_ddos_notice(c, query);

}
event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    generate_ddos_notice(c, query);

}
