global addr_agent_number : table[addr] of set[string] = table();

event http_header (c: connection, is_orig: bool, name: string, value: string){
	if(c$http?$user_agent){
		local ip=c$id$orig_h;
		local user_agent=to_lower(c$http$user_agent);
		if(ip in addr_agent_number){
			add (addr_agent_number[ip])[user_agent];
		}else{
			addr_agent_number[ip]=set(user_agent);
		}
	}
}

event zeek_done() {
	for (ip in addr_agent_number) {
	    if (|addr_agent_number[ip]| >= 3) {
	        print fmt("alert! %s has proxy", ip);
	    }
	}
}
