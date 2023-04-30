event krb_as_response(c: connection,msg: KRB::KDC_Response) {
    if (c$id$orig_h == 172.17.1.129) {
        print fmt("User account name: %s", msg$client_name);
    }
}
