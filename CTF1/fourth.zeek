@load policy/frameworks/files/extract-all-files
@load base/files/hash/main.zeek

# Define a function that filters the extracted files to only show those with a MIME type of "msword"
#global x;
 
function filter_exe(f: fa_file) {
    if (f?$info && f$info?$mime_type && f$info$mime_type == "application\/x-dosexec") {
        #print f$info$mime_type, f$info$filename;
        #x=f$info$filename;
        print fmt("New Microsoft Word document: %s", f$source);
        print f$http$host+f$http$uri;
        print f$http$ts;
        local ts=(f$http$ts);
        local dt: string = strftime("%Y-%m-%d %H:%M:%S", ts);
    	print dt;
    }
}

# Hook into the file extraction events to apply the filter function
event file_sniff(f: fa_file, meta: fa_metadata) {
    filter_exe(f);
}
