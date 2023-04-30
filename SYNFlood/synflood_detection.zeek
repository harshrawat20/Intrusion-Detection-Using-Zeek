# Define a module named SYNFLOOD
module SYNFLOOD;

# Set the SYN_THRESHOLD constant to 50
const SYN_THRESHOLD: count = 50;

# Add a new enumeration value SYNFlood to the Notice::Type enumeration
redef enum Notice::Type += {
    SYNFlood
};

# Define a function to generate a notice for potential SYN flood attacks
function generate_syn_notice(c: connection, pkt: SYN_packet) {
    # Check if the size of the SYN packet is greater than the SYN_THRESHOLD constant
    if(pkt$size > SYN_THRESHOLD) {
        # If it is, generate a new notice of type SYNFlood with a message indicating a potential SYN flood attack
        NOTICE([$note = SYNFlood,
            $msg = fmt("Potential SYN flood detected from %s to %s", c$id$orig_h, c$id$resp_h),
            $conn = c,
            $uid = c$uid
        ]);
    }
}

# Define an event handler for SYN packets on new connections
event connection_SYN_packet(c: connection, pkt: SYN_packet) {
    # Call the generate_syn_notice function with the connection and SYN packet objects as arguments
    generate_syn_notice(c, pkt);
}
