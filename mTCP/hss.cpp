#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <set>
#include <map>
#include <mutex>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "packet.h"
#include "common.h"
#include "utils.h"
#include "security.h"
#include "cpu.h"
#include "debug.h"
#include "mtcp_api.h"
#include "mtcp_epoll.h"
#include "uecontext.h"
#include "hss.h"

#include <sys/epoll.h>



#define MAX_THREADS 1 // This constant defines number of threads used by HSS 

struct hssdata
{
	int key_id,rand_num;// rand_num is used for generating authentication challenge
	uint64_t scscfport; // Scscf port number
	string scscfaddress;// Scscf IP address
};

//inMemoryDatabase is map of IMSI and its corresponding data.
std::map<uint64_t, hssdata> inMemoryDatabase;

/*
This setupkv function sets up inMemoryDatabase from IMSI 119000000000 to 119000000999.
*/
void setupkv()
{
	struct hssdata myvar;	
	uint64_t imsi = 119000000000;
	for(imsi = 119000000000; imsi <= 119000000999; imsi++)
	{
		myvar.key_id = imsi%1000;	// We are setting up inMemoryDatabase just for 1000 RAN threads.
		myvar.rand_num = myvar.key_id+2;
		inMemoryDatabase[imsi] = myvar;
		inMemoryDatabase[imsi].scscfport =SCSCFPORTNO;
		inMemoryDatabase[imsi].scscfaddress = SCSCFADDR;
	}
}

map<uint64_t,UEcontext> uecontextmap; // For storing UE context
mutex uecontextmap_lock; // This lock will serve for locking uecontextmap

struct arg{
	int id;
	int coreno;
};
struct arg arguments[MAX_THREADS]; // Arguments sent to Pthreads

pthread_t servers[MAX_THREADS]; // Threads 

//Function handler to handle program exit
void SignalHandler(int signum)
{
	mtcp_destroy();	
}

//Handle error function to exit when error occurs.
void handle_error(string msg)
{
  perror(msg.c_str()); 
  exit(EXIT_FAILURE); 
}

//Handle error function to exit when error occurs.
void handle_epoll_error(string msg)
{
  perror(msg.c_str()); 
  cout<<errno<<endl;
  
  //exit(EXIT_FAILURE); 
}


void * run(void* arg1)
{
	struct arg argument = *((struct arg*)arg1); // Get argument 
	int core = argument.coreno; 
	mctx_t mctx ; // Get mtcp context

	int ran_listen_fd; 	// This fd will be initial listen id
	int ran_accept_fd; 	
	int shouldbeZero;		


	//Structure variable storing I-CSCF server address
	struct sockaddr_in hss_server_addr;


	
	//Initialize I-CSCF Address
	bzero((char *) &hss_server_addr, sizeof(hss_server_addr)); // Set it to zero
	hss_server_addr.sin_family = AF_INET;												// Address family = Internet
	hss_server_addr.sin_addr.s_addr = inet_addr(HSSADDR);			//Get IP address of HSS from common.h	
	hss_server_addr.sin_port = htons(HSSPORTNO);							//Get port number of HSS from common.h
	
	/*
	fddata variable stores various connection variables and context of connection.
	fdmap is Map to store each file descriptor's corresponding information
	*/	
	struct mdata fddata;
	map<int, mdata> fdmap;

	//step 2. mtcp_core_affinitize
	mtcp_core_affinitize(core);
	//step 3. mtcp_create_context. Here order of affinitization and context creation matters.
	// mtcp_epoll_create
	
	mctx = mtcp_create_context(core);
	if (!mctx) {
		handle_error("Failed to create mtcp context!\n");
	}
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);	


	
	ran_listen_fd = mtcp_socket(mctx,AF_INET, SOCK_STREAM , 0); // Create NON blocking socket for listening

	if(ran_listen_fd == -1) // Error occured in socket creation
	{
			handle_error("HSS is not able to create new socket for listening\n");
	}

	shouldbeZero = mtcp_setsock_nonblock(mctx, ran_listen_fd);
	if (shouldbeZero < 0) 
	{
		handle_error("Failed to set socket in nonblocking mode.\n");
	}		
	

	if(mtcp_bind(mctx,ran_listen_fd, (struct sockaddr *) &hss_server_addr, sizeof(hss_server_addr)) == -1) // Bind
	{
			handle_error("HSS is not able to bind socket for listening\n");
	}

	if(mtcp_listen(mctx,ran_listen_fd, MAXCONN) == -1) // If listen failed give error
	{
			handle_error("HSS is not able to listen\n");
	}

	// File descriptor for Epoll
	int epollfd,cur_fd; 
	int epoll_error_count = 0;

	//Variable to store act_type
	int act_type;
	
	//Epoll variables to handle events
	struct mtcp_epoll_event new_file_descriptor_to_watch; 		// New file descriptor to add to epoll
	struct mtcp_epoll_event current_event;						// Variable to store event we are currently processing
	struct mtcp_epoll_event *events_received;					// Stores all events received for processing

	epollfd = mtcp_epoll_create(mctx,MAXEVENTS); // MAXEVENTS is ignored here
	if(epollfd == -1) handle_error("Error in epoll_create");

	//Initialize EPoll fields for listening to sockets.
	new_file_descriptor_to_watch.data.sockid = ran_listen_fd;
	new_file_descriptor_to_watch.events = MTCP_EPOLLIN | MTCP_EPOLLET | MTCP_EPOLLRDHUP;
	shouldbeZero = mtcp_epoll_ctl(mctx,epollfd, MTCP_EPOLL_CTL_ADD, ran_listen_fd, &new_file_descriptor_to_watch);

	if(shouldbeZero == -1)
	{
		handle_error("Error in epoll_ctl");
	}

	// Allocate memory to hold data 
	events_received = (mtcp_epoll_event *) malloc (sizeof (struct mtcp_epoll_event) * MAXEVENTS);
	if(events_received == NULL)
	{
		handle_error("Failed to allocate memory to events_received");
	}

	int firstPrintInWhile= 0; 
	int number_of_events; 

	while(true) // Wait forever 
	{
		if(firstPrintInWhile == 0)
		{
			cout<<"We are inside while"<<endl;
			firstPrintInWhile = 1;
		}
		number_of_events = mtcp_epoll_wait(mctx,epollfd, events_received, MAXEVENTS, -1);

		if(number_of_events == 0) //Timeout go back to waiting
		{
			cout<<"Timeout occured\n";
			continue;
		}
		else if(number_of_events == -1) // Epoll wait failed
		{
			handle_error("Error is epoll_wait\n");
		}

		for(int i = 0; i < number_of_events; ++i) // Go over all events
		{
			if(events_received[i].events & MTCP_EPOLLERR)
			{
				//If any error occurs, do cleanup
				mtcp_close(mctx,events_received[i].data.sockid);
				handle_epoll_error("EPOLLERR occured\n");
				epoll_error_count++;
				cout<<"EPOLL ERROR NUMBER "<<epoll_error_count<<endl;
				mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_DEL, events_received[i].data.sockid, NULL); // Delete from EPOLL
				cur_fd = events_received[i].data.sockid; 	// Get current File descriptor
				fddata = fdmap[cur_fd];					
				act_type = fddata.act;			
				cout<<"ERROR at "<<act_type<<endl;			//Action to be performed
			}
			else if(events_received[i].events & MTCP_EPOLLHUP)
			{
				close(events_received[i].data.sockid);
				handle_error("EPOLLHUP unexpected close of the socket, i.e. usually an internal error");
			}
			else
			{
				current_event = events_received[i];

				if(current_event.data.sockid == ran_listen_fd) // Got receive 
				{
					while(1) // Accept all events.
					{
						ran_accept_fd = mtcp_accept(mctx,ran_listen_fd, NULL, NULL); // Accept the connection

						if(ran_accept_fd == -1)
						{
							if((errno == EAGAIN) || (errno == EWOULDBLOCK)) // We went through all the connections, exit the loop
								break;
							else
								handle_error("Error while accepting connection"); 				
						}

						//Add newly accepted connection for reading
						new_file_descriptor_to_watch.data.sockid = ran_accept_fd;
						new_file_descriptor_to_watch.events = MTCP_EPOLLIN ;

						shouldbeZero = mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_ADD, ran_accept_fd, &new_file_descriptor_to_watch); // Add to epoll

						if(shouldbeZero == -1)
						{ 
							handle_error("Error in epoll_ctl on Accept");
						}

						//Set buffers , later useful while waiting
						fddata.act = 1;
						fddata.initial_fd = 0;
						memset(fddata.buf,0,mdata_BUF_SIZE);
						fddata.buflen = 0;
						fdmap.insert(make_pair(ran_accept_fd,fddata));
					}
				}
				else
				{
					cur_fd = current_event.data.sockid; 	// Get current File descriptor
					fddata = fdmap[cur_fd];					
					act_type = fddata.act;					//Action to be performed

					switch(act_type)
					{
						case 1: // There is only single action in HSS
							if(events_received[i].events & MTCP_EPOLLIN)
							{
								handleRegistrationRequest(mctx,epollfd,cur_fd,fdmap,fddata,ICSCFADDR,ICSCFPORTNO,new_file_descriptor_to_watch);
							}
							else
							{
								handle_error("Its not EPOLLIN in case 1");
							}
						break;

						default:
						cout<<"Action type not known"<<cur_fd<<" "<<act_type<<endl;
						break;
					}
				}
			}
		}
	}
}

int main()
{

    char* conf_file = "server.conf"; //Server.conf
	setupkv();  // Initialize In memory database of 999 Identities.
    int ret;
    /* initialize mtcp */
	if (conf_file == NULL)
	{
		cout<<"You forgot to pass the mTCP startup config file!\n";
		exit(EXIT_FAILURE);
	}
	else
	{
		TRACE_INFO("Reading configuration from %s\n",conf_file);
	}

	//step 1. mtcp_init, mtcp_register_signal(optional)
	ret = mtcp_init(conf_file);
	if (ret) {
		cout<<"Failed to initialize mtcp\n";
		exit(EXIT_FAILURE);
	}
	
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);


	//spawn server threads
	for(int i=0;i<MAX_THREADS;i++){
		arguments[i].coreno = i;
		arguments[i].id = i;
		pthread_create(&servers[i],NULL,run,&arguments[i]);
	}


	//Wait for server threads to complete
	for(int i=0;i<MAX_THREADS;i++){
		pthread_join(servers[i],NULL);		
	}

	return 0;
}
/*
This function performs takes various actions based on originator of request and stage of request processing.
Parameters
mctx : mtcp context used for doing calls to various mtcp methods.
cur_fd : Current fuile descriptor on which event was received.
epollfd : Used for adding new epoll events
ServerAddress,port,new_file_descriptor_to_watch : Not used
 
*/
int handleRegistrationRequest(mctx_t &mctx,int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata,  char * ServerAddress, int port, mtcp_epoll_event &new_file_descriptor_to_watch)
{
		Packet pkt;
		char * dataptr; // Pointer to data for copying to packet
		char data[BUF_SIZE]; // To store received packet data
		uint64_t imsi,vmid; // vmid is used to identify whether request is from I-CSCF or S-CSCF.
		int packet_length;
		int returnval;  
		pkt.clear_pkt();
		bool res; // To store result of HMAC check
		int hssStatus;	
		uint64_t scscfport ;	// for Sending SCSCF port number
		string scscfaddress;	//and address
		string okay  = "200 OK"; 
		string failed = "500 FAIL";
		string unauthenticated = "401 UNAUTHENTICATED";	
		UEcontext current_context;

		mtcp_epoll_ctl(mctx, epollfd, MTCP_EPOLL_CTL_DEL, cur_fd, NULL); // Delete from EPOLL

		returnval = mtcp_read(mctx,cur_fd, data, BUF_SIZE);	//Read packet length

		if(returnval == 0) // This means connection closed at other end
			{
				close(cur_fd);
				fdmap.erase(cur_fd);		
				return 0;
			}
			else if(returnval < 0)
			{
				handle_error("Error occured at HSS while trying to read packet length");
			}
			else
			{
				memmove(&packet_length, data, sizeof(int)); // Move packet length into packet_len
				
				if(packet_length <= 0) 
				{
						perror("Error in reading packet_length\n");
						cout<<errno<<endl;
				}
				//Logic for moving the packet data from Data to packet pkt
				pkt.clear_pkt();
				dataptr = data+sizeof(int);
				memcpy(pkt.data, (dataptr), packet_length);
				pkt.data_ptr = 0;
				pkt.len = packet_length;			

					TRACE(cout<<"Packet read "<<returnval<<" bytes instead of "<<packet_length<<" bytes";)

					pkt.extract_sip_hdr();
					
					if (HMAC_ON) { // Check HMACP
					res = g_integrity.hmac_check(pkt, 0);
					if (res == false) 
						{
						TRACE(cout << "scscf/icscf->hss:" << " hmac failure: " << endl;)
						g_utils.handle_type1_error(-1, "hmac failure: scscf/icscf->hss");
						}		
					} 
					if (ENC_ON) { // Decryption
						g_crypt.dec(pkt, 0);
					} 	

					pkt.extract_item(imsi);
					pkt.extract_item(vmid);										

					// if vmid is 1000 then request is from I-CSCF else from S-CSCF.				
					switch(vmid)
					{
						case 1000:
						TRACE(cout<<"ICSCF->hss"<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
						switch(pkt.sip_hdr.msg_type)
						{
							case 1:
							current_context.imsi = imsi;
							pkt.extract_item(current_context.instanceid);										
							pkt.extract_item(current_context.expiration_value);										
							pkt.extract_item(current_context.integrity_protected);
							TRACE(cout<<"IMSI "<<imsi<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)

							uecontextmap_lock.lock(); // Locks before updating uecontextmap
							uecontextmap[imsi]=current_context;
							uecontextmap_lock.unlock();								
							break;

							case 2: // Case 2 has similar process to getting address of SCSCF as that of case 1
							uecontextmap_lock.lock(); // Locks before updating uecontextmap
							current_context=uecontextmap[imsi];
							uecontextmap_lock.unlock();		

							pkt.extract_item(current_context.instanceid);										
							pkt.extract_item(current_context.expiration_value);										
							pkt.extract_item(current_context.integrity_protected);
							TRACE(cout<<"IMSI received for Auth, sending SCSCF Address back"<<imsi<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)

							uecontextmap_lock.lock(); // Locks before updating uecontextmap
							uecontextmap[imsi]=current_context;
							uecontextmap_lock.unlock();		
							break;
							

							case 3:
							uecontextmap_lock.lock(); // Locks before updating uecontextmap
							current_context=uecontextmap[imsi];
							uecontextmap_lock.unlock();		

							pkt.extract_item(current_context.instanceid);										
							pkt.extract_item(current_context.expiration_value);										
							pkt.extract_item(current_context.integrity_protected);
							TRACE(cout<<"IMSI received for Dergister, sending SCSCF Address back"<<imsi<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)

							uecontextmap_lock.lock(); // Locks before updating uecontextmap
							uecontextmap[imsi]=current_context;
							uecontextmap_lock.unlock();			
								break;
						}						
						break;
						case 1001:
						TRACE(cout<<"SCSCF->hss"<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)	
						switch(pkt.sip_hdr.msg_type)
						{
							case 1:
								break;
							case 2:
								uecontextmap_lock.lock(); // Locks before updating uecontextmap
								current_context=uecontextmap[imsi];
								uecontextmap_lock.unlock();									
								pkt.extract_item(current_context.registered);						
								uecontextmap_lock.lock(); // Locks before updating uecontextmap
								uecontextmap[imsi]=current_context;
								uecontextmap_lock.unlock();		
							break;
							case 3:
								uecontextmap_lock.lock(); // Locks before updating uecontextmap
								current_context=uecontextmap[imsi];
								uecontextmap_lock.unlock();
								pkt.extract_item(current_context.instanceid);
								pkt.extract_item(current_context.expiration_value);
								pkt.extract_item(current_context.integrity_protected);

								if(current_context.expiration_value == 0)
								{
									TRACE(cout<<"Deregistration request in progress for"<<imsi<<endl;)
									current_context.registered = 0;
								}								
								else
								{
									cout<<"ERROR in Deregistration for"<<imsi<<endl;
								}
								uecontextmap_lock.lock(); // Locks before updating uecontextmap
								uecontextmap[imsi]=current_context;
								uecontextmap_lock.unlock();										

							break;							
						}											
						break;
					}					

																

					fddata.sipheader = pkt.sip_hdr.msg_type;
					

					pkt.clear_pkt();
					pkt.append_item(imsi); 
					switch(vmid)
					{
					case 1000:	//Send SCSCF address to ICSCF
						switch(fddata.sipheader)
						{
							case 1: 
							case 2:
							case 3:							
							hssStatus = get_scscf(imsi,scscfaddress,scscfport);
							pkt.append_item(hssStatus);
							pkt.append_item(scscfaddress);
							pkt.append_item(scscfport);
							break;

						}					
					break;
					case 1001:
						switch(fddata.sipheader)
						{
							case 1: // Send Authentication information to SCSCF
							handle_autninfo_req(pkt,imsi);
							break;
							case 2: //Check registration status and reply accordingly
							if(current_context.registered == 1)
							{
								TRACE(cout<<"Registration successful for imsi "<<imsi<<endl;)
								pkt.append_item(okay);																			
							}							
							else
							{
								cout<<"Registration failed for imsi "<<imsi<<endl;
								pkt.append_item(failed);												
							}														
							break;
							case 3: //Remove UEcontext post de-registration
							pkt.append_item(current_context.registered);

							uecontextmap_lock.lock(); 
							if(uecontextmap.erase(imsi) ==0) cout<<"Unable to find "<<imsi<<" in map"<<endl;

							uecontextmap_lock.unlock();																	

							if(current_context.registered == 0)
							{
								TRACE(cout<<"Deregistration successful for"<<imsi<<endl;)
							}
							else
							{
								cout<<"ERROR in Deregistration\n";
							}
							break;							
						}

					break;

					}


					if (ENC_ON) // Add encryption
					{
						g_crypt.enc(pkt,0); 
					}
					if (HMAC_ON)  // Add HMAC
					{
						g_integrity.add_hmac(pkt, 0);
					} 

					pkt.prepend_sip_hdr(fddata.sipheader);								
					pkt.prepend_len();
					
					returnval = mtcp_write(mctx,cur_fd, pkt.data, pkt.len);

					switch(vmid)
					{
					case 1000:
					if(returnval > 0)
						TRACE(cout<<"Sent HSS-ICSCF "<<fddata.sipheader<<endl;)
					if(returnval < 0)
						handle_error("Error occured while trying to write to ICSCF\n");
					break;
					case 1001:
					if(returnval > 0)
						TRACE(cout<<"Sent HSS-SCSCF "<<fddata.sipheader<<endl;)
					if(returnval < 0)
						handle_error("Error occured while trying to write to SCSCF\n");					
					break;
					}
				
					if(returnval == -1)
						{ 
								handle_error("Error in epoll_ctl on Accept");
						}

					fdmap.erase(cur_fd);
					mtcp_close(mctx,cur_fd);
					}								
				 
}

/*
This function "get_scscf" checks whether imsi exists in inMemoryDatabase,
if it exists then it retrievs scscfaddress belonging to it. 
It returns 0 if it can not find imsi in inMemoryDatabase.
*/

int get_scscf(uint64_t imsi,string &scscfaddress,uint64_t &scscfport) 
{
	if(inMemoryDatabase.find(imsi) == inMemoryDatabase.end())
	{
		return 0;	
	}
	else
	{
		scscfaddress = inMemoryDatabase[imsi].scscfaddress;
		scscfport = inMemoryDatabase[imsi].scscfport;		
		return 1;
	}
}
/*
This function computes various parameters required for authentication procedure and then append them to packet.
*/
void handle_autninfo_req(Packet &pkt, uint64_t imsi) {
	uint64_t key;
	uint64_t rand_num;
	uint64_t autn_num;
	uint64_t sqn;
	uint64_t xres;
	uint64_t ck;
	uint64_t ik;
	uint64_t k_asme;
	uint64_t num_autn_vectors;
	uint16_t plmn_id;
	uint16_t nw_type;


	get_autn_info(imsi, key, rand_num);
	TRACE(cout << "hss_handleautoinforeq:" << " retrieved from database: " << imsi << endl;)
	sqn = rand_num + 1;
	xres = key + sqn + rand_num;
	autn_num = xres + 1;
	ck = xres + 2;
	ik = xres + 3;
	k_asme = ck + ik + sqn + plmn_id;
	TRACE(cout << "hss_handleautoinforeq:" << " autn:" << autn_num << " rand:" << rand_num << " xres:" << xres << " k_asme:" << k_asme << " " << imsi << endl;)
	pkt.append_item(autn_num);
	pkt.append_item(rand_num);
	pkt.append_item(xres);
	pkt.append_item(k_asme);
	TRACE(cout<<"Managed to send authorization stuff"<<autn_num<<" "<<rand_num<<" "<<xres<<" "<<k_asme<<endl;)
	TRACE(cout<<"hss_handleautoinforeq:" << " response sent to scscf: " << imsi << endl;)
}
/*
This function retrieves key and rand_num from inMemoryDatabase. 
*/
void get_autn_info(uint64_t imsi, uint64_t &key, uint64_t &rand_num) {
	key = inMemoryDatabase[imsi].key_id;
	rand_num = inMemoryDatabase[imsi].rand_num;

}