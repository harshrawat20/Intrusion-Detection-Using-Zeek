# Define a new module named "DDosAttacks"
module DDosAttacks;

# Add a new type of notice to the existing set of notice types
redef enum Notice::Type += {
    DNSDDoSAmplification
};

# Define a function named "generate_ddos_notice"
function generate_ddos_notice(c: connection, query: string) {
    # Remove any whitespace from the DNS query string
    local query1: string = strip(query);

    # Check if the query is equal to either "peacecorps.gov" or "pizzaseo.com"
    if (query1 == "peacecorps.gov" || query1 == "pizzaseo.com") {
        # Generate a new notice of type DNSDDoSAmplification if the query matches
        NOTICE([$note = DNSDDoSAmplification,
            $msg = fmt("Possible DNS DDoS Amplification Attack"),
            $conn = c,
            $uid = c$uid
        ]);
    }
    else {
        # Generate a new notice of type DNSDDoSAmplification if the query does not match
        NOTICE([$note = DNSDDoSAmplification,
            $msg = fmt("Not a DNS DDoS Amplification Attack"),
            $conn = c,
            $uid = c$uid
        ]);
    }
}

# Define an event handler for DNS requests
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    # Call the "generate_ddos_notice" function with the connection object and DNS query string as parameters
    generate_ddos_notice(c, query);
}

# Define an event handler for DNS query replies
event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    # Call the "generate_ddos_notice" function with the connection object and DNS query string as parameters
    generate_ddos_notice(c, query);
}
