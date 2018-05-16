int handleRegistrationRequest(mctx_t &mctx,int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata,  char * ServerAddress, int port, mtcp_epoll_event &new_file_descriptor_to_watch);
int handlecase3(mctx_t &mctx,int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata,  char * ServerAddress, int port, mtcp_epoll_event &new_file_descriptor_to_watch);
