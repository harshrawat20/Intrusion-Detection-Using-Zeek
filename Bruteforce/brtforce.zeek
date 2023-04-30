# Load a script that detects SSH brute-force attacks
@load protocols/ssh/detect-bruteforcing

# Set the maximum number of password guesses to 3 for SSH connections
redef SSH::password_guesses_limit=3;

# Set the guessing timeout to 60 minutes for SSH connections
redef SSH::guessing_timeout=60 mins;

# Define an event handler that creates a debug plugin and activates it with a debug level of 0
event NetControl::init() {
    local debug_plugin = NetControl::create_debug(T);
    NetControl::activate(debug_plugin, 0);
}

# Define a hook that will be called whenever a new notice is generated
hook Notice::policy(n: Notice::Info) {
    # Check if the notice is of type SSH::Password_Guessing
    if ( n$note == SSH::Password_Guessing ) {
        # Drop the address of the attacker for 60 minutes using NetControl::drop_address()
        NetControl::drop_address(n$src, 60min);

        # Add Notice::ACTION_DROP and Notice::ACTION_LOG to the notice's actions
        add n$actions[Notice::ACTION_DROP];
        add n$actions[Notice::ACTION_LOG];
    }
}
