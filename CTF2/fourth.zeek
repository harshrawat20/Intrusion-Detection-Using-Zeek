@load policy/frameworks/files/extract-all-files
@load base/files/hash/main.zeek
@load base/utils/numbers
@load base/utils/files
@load base/frameworks/tunnels
@load base/protocols/conn/removal-hooks

# Define a function that filters the extracted files to only show those with a MIME type of "windows executable"
 
function filter_exe(f: fa_file) {
    if (f?$info && f$info?$mime_type && f$info$mime_type == "application\/x-dosexec") {
        print f$info$mime_type, f$info$filename;
        print fmt("New windows executable file: %s", f$source);
        print f$http$host+f$http$uri;
        print f$http$ts;
        local ts=(f$http$ts);
        local dt: string = strftime("%Y-%m-%d %H:%M:%S", ts);
    	print dt;
	print f$http$response_body_len;
    }
}

# Hook into the file extraction events to apply the filter function
event file_sniff(f: fa_file, meta: fa_metadata) {
    filter_exe(f);
}

