int handleRegistrationRequest(mctx_t &mctx,int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata,  char * ServerAddress, int port, mtcp_epoll_event &new_file_descriptor_to_watch);
int get_scscf(uint64_t imsi,string &scscfaddress,uint64_t &scscfport);
void handle_autninfo_req(Packet &pkt, uint64_t imsi);
void get_autn_info(uint64_t imsi, uint64_t &key, uint64_t &rand_num);
