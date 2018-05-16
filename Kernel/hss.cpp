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
#include "icscf.h"
#include "utils.h"
#include "hss.h"
#include "security.h"
#include "uecontext.h"
#include <sys/epoll.h>


#define MAX_THREADS 3 // This constant defines number of threads used by HSS 


struct hssdata
{
	int key_id,rand_num; // rand_num is used for generating authentication challenge
	uint64_t scscfport;  // Scscf port number
	string scscfaddress; // Scscf IP address
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
		inMemoryDatabase[imsi].scscfaddress = SCSCFADDR; // Save SCSCF address 
	}
}

struct arg{
	int id;
	int coreno;
};

struct arg arguments[MAX_THREADS]; // Arguments sent to Pthreads

pthread_t servers[MAX_THREADS]; // Threads 

mutex listen_lock; // This lock will serve for locking socket

int ran_listen_fd; 	// This fd will be initial listen id

map<uint64_t,UEcontext> uecontextmap; // For storing UE context

mutex uecontextmap_lock; // This lock will serve for locking uecontextmap

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
}

void * run(void* arg1)
{
	int ran_accept_fd; 	// This is accept ID.
	int shouldbeZero;	

	/* fddata variable stores various connection variables and context of connection. */
	struct mdata fddata;	

	/* Map to store each file descriptor's corresponding information	*/
	map<int, mdata> fdmap;

	// File descriptor for Epoll
	int epollfd,cur_fd; 

	//act_type : describes current action being performed by HSS
	int act_type;
	
	//Epoll variables to handle events
	struct epoll_event new_file_descriptor_to_watch;// New file descriptor to add to epoll
	struct epoll_event current_event; 				// Variable to store event we are currently processing
	struct epoll_event *events_received;			// Stores all events received for processing

	epollfd = epoll_create(MAXEVENTS); // MAXEVENTS is ignored here
	if(epollfd == -1) handle_error("Error in epoll_create");

	//	Lock listen_lock to enable multiple threads to listen on same file descriptor.
	listen_lock.lock();				

	//Initialize EPoll fields for listening to sockets.
	new_file_descriptor_to_watch.data.fd = ran_listen_fd;
	new_file_descriptor_to_watch.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
	shouldbeZero = epoll_ctl(epollfd, EPOLL_CTL_ADD, ran_listen_fd, &new_file_descriptor_to_watch);

	if(shouldbeZero == -1)
	{
		handle_error("Error in epoll_ctl");
	}
	listen_lock.unlock();

	// Allocate memory to hold data 
	events_received = (epoll_event *) malloc (sizeof (struct epoll_event) * MAXEVENTS);
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
		number_of_events = epoll_wait(epollfd, events_received, MAXEVENTS, -1);

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
			if(events_received[i].events & EPOLLERR)
			{
				close(events_received[i].data.fd);
				handle_epoll_error("EPOLLERR occured\n");
			}
			else if(events_received[i].events & EPOLLHUP)
			{
				close(events_received[i].data.fd);
				handle_epoll_error("EPOLLHUP unexpected close of the socket, i.e. usually an internal error");
			}
			else
			{
				current_event = events_received[i];

				if(current_event.data.fd == ran_listen_fd) //If event in listening fd, its new connection
				{
					while(1) // Accept all events.
					{

						ran_accept_fd = accept(ran_listen_fd, NULL, NULL); // Accept the connection

						if(ran_accept_fd == -1)
						{
							if((errno == EAGAIN) || (errno == EWOULDBLOCK)) // We went through all the connections, exit the loop
								break;
							else
								handle_error("Error while accepting connection"); 				
						}

						//Add newly accepted connection for reading
						new_file_descriptor_to_watch.data.fd = ran_accept_fd;
						new_file_descriptor_to_watch.events = EPOLLIN ;

						shouldbeZero = epoll_ctl( epollfd, EPOLL_CTL_ADD, ran_accept_fd, &new_file_descriptor_to_watch); // Add to epoll

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
					cur_fd = current_event.data.fd; // Get current File descriptor
					fddata = fdmap[cur_fd];					
					act_type = fddata.act;			//Action to be performed

					switch(act_type) 
					{
						case 1: // There is only single action in HSS
							if(events_received[i].events & EPOLLIN)
							{
								handleRegistrationRequest(epollfd,cur_fd,fdmap,fddata,ICSCFADDR,ICSCFPORTNO,new_file_descriptor_to_watch);
							}
							else
							{
								handle_epoll_error("Its not EPOLLIN in case 1");
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
	//Structure variable storing I-CSCF server address
	struct sockaddr_in hss_server_addr;
	//Initialize I-CSCF Address
	bzero((char *) &hss_server_addr, sizeof(hss_server_addr)); 							// Set it to zero
	hss_server_addr.sin_family = AF_INET;												// Address family = Internet
	hss_server_addr.sin_addr.s_addr = inet_addr(HSSADDR);								//Get IP address of I-CSCF from common.h	
	hss_server_addr.sin_port = htons(HSSPORTNO);										//Get port number of I-CSCF from common.h

	ran_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0); // Create NON blocking socket for listening

	if(ran_listen_fd == -1) // Error occured in socket creation
	{
			handle_error("HSS is not able to create new socket for listening\n");
	}
	

	if(bind(ran_listen_fd, (struct sockaddr *) &hss_server_addr, sizeof(hss_server_addr)) == -1) // Bind
	{
			handle_error("HSS is not able to bind socket for listening\n");
	}

	if(listen(ran_listen_fd, MAXCONN) == -1) // If listen failed give error
	{
			handle_error("HSS is not able to listen\n");
	}

	setupkv(); // In memory database of 999 Identities.
 
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
cur_fd : Current file descriptor on which event was received.
epollfd : Used for adding new epoll events
ServerAddress,port,new_file_descriptor_to_watch : Not used
*/
int handleRegistrationRequest(int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata,  char * ServerAddress, int port, epoll_event &new_file_descriptor_to_watch)
{
		Packet pkt;
		char * dataptr; 	// Pointer to data for copying to packet
		char data[BUF_SIZE]; 	// To store received packet data
		uint64_t imsi,vmid;	// vmid is used to identify whether request is from I-CSCF or S-CSCF.
		int packet_length;
		int returnval; 	
		pkt.clear_pkt();
		bool res; 		// To store result of HMAC check
		UEcontext current_context; // Stores current UEContext
		int hssStatus;	
		uint64_t scscfport ;	// for Sending SCSCF port number
		string scscfaddress;	//and address
		string okay  = "200 OK"; 
		string failed = "500 FAIL";
		string unauthenticated = "401 UNAUTHENTICATED";		

		returnval = read(cur_fd, data, BUF_SIZE);	//Read packet

		if(returnval == 0) // This means connection closed at other end
			{
				close(cur_fd);
				fdmap.erase(cur_fd);		
				return 0;
			}
		else if(returnval < 0)
			{
				handle_error("Error occured at hss while trying to read packet lengthfrom HSS in Register");
			}
		else
			{
				memmove(&packet_length, data, sizeof(int)); // Move packet length into packet_len
				
				if(packet_length <= 0) 
				{
						perror("Error in reading packet_length\n");
						cout<<errno<<endl;
				}
				//Logic for moving the packet "data" from Data to packet "pkt"
				pkt.clear_pkt();
				dataptr = data+sizeof(int);
				memcpy(pkt.data, (dataptr), packet_length);
				pkt.data_ptr = 0;
				pkt.len = packet_length;			

					TRACE(cout<<"Packet read "<<returnval<<" bytes instead of "<<packet_length<<" bytes"<<endl;)

					pkt.extract_sip_hdr();
					
					
					if (HMAC_ON) { // Check HMACP
					res = g_integrity.hmac_check(pkt, 0);
					if (res == false) 
						{
						TRACE(cout << "icscf->hss:" << " hmac failure: " << endl;)
						g_utils.handle_type1_error(-1, "hmac failure: icscf->hss");
						}		
					} 
					if (ENC_ON) { // Decryption
						g_crypt.dec(pkt, 0);
					} 	

					pkt.extract_item(imsi);
					pkt.extract_item(vmid);										
					TRACE(cout<<"ICSCF->hss"<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)
					// if vmid is 1000 then request is from I-CSCF else from S-CSCF.
					switch(vmid)
					{
						case 1000:
							TRACE(cout<<"received"<<vmid<<"from ICSCF\n";)
							switch(pkt.sip_hdr.msg_type)
							{
								case 1: // Case 1, message recieived from ICSCF->HSS for getting address of SCSCF
								current_context.imsi = imsi;
								pkt.extract_item(current_context.instanceid);										
								pkt.extract_item(current_context.expiration_value);										
								pkt.extract_item(current_context.integrity_protected);
								TRACE(cout<<"IMSI received for Reg, sending SCSCF Address back"<<imsi<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)

								uecontextmap_lock.lock(); // Locks before updating uecontextmap
								uecontextmap[imsi]=current_context;
								uecontextmap_lock.unlock();				
								break;

								case 2: // Case 2 has similar process to getting address of SCSCF as that of case 1
								uecontextmap_lock.lock(); // Locks before updating uecontextmap
								current_context=uecontextmap[imsi];
								uecontextmap_lock.unlock();		
								TRACE(cout<<"IMSI received for Auth, sending SCSCF Address back"<<imsi<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)

								pkt.extract_item(current_context.instanceid);										
								pkt.extract_item(current_context.expiration_value);										
								pkt.extract_item(current_context.integrity_protected);

								uecontextmap_lock.lock(); // Locks before updating uecontextmap
								uecontextmap[imsi]=current_context;
								uecontextmap_lock.unlock();			
								break;

								case 3:
								uecontextmap_lock.lock(); // Locks before updating uecontextmap
								current_context=uecontextmap[imsi];
								uecontextmap_lock.unlock();		
								TRACE(cout<<"IMSI received for Dergister, sending SCSCF Address back"<<imsi<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)

								pkt.extract_item(current_context.instanceid);										
								pkt.extract_item(current_context.expiration_value);										
								pkt.extract_item(current_context.integrity_protected);

								uecontextmap_lock.lock(); // Locks before updating uecontextmap
								uecontextmap[imsi]=current_context;
								uecontextmap_lock.unlock();										
								break;
							}
							break;
						case 1001:
							TRACE(cout<<"received"<<vmid<<"from SCSCF\n";)
							switch(pkt.sip_hdr.msg_type)
							{							
								case 1:	//Do nothing
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
					}

					fddata.sipheader = pkt.sip_hdr.msg_type;
					

					pkt.clear_pkt();
					pkt.append_item(imsi); 
					switch(vmid)
					{
					case 1000:  //Send SCSCF address to ICSCF
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
							case 3://Remove UEcontext post de-registration
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
					
					returnval = write(cur_fd, pkt.data, pkt.len);

					if(returnval > 0)
						TRACE(cout<<"Sent HSS->ICSCF "<<fddata.sipheader<<endl;)
					if(returnval < 0)
						handle_error("Error occured while trying to write to ICSCF\n");
						
					if(returnval == -1)
						{ 
								handle_error("Error in epoll_ctl on Accept");
						}
					epoll_ctl(epollfd, EPOLL_CTL_DEL, cur_fd, NULL);
					fdmap.erase(cur_fd);
					close(cur_fd);	
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

//	This function computes various parameters required for authentication procedure and then append them to packet.

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
	TRACE(cout << "hss_handleautoinforeq:" << " response sent to scscf: " << imsi << endl;)
}

//	This function retrieves key and rand_num from inMemoryDatabase. 

void get_autn_info(uint64_t imsi, uint64_t &key, uint64_t &rand_num) {
	key = inMemoryDatabase[imsi].key_id;
	rand_num = inMemoryDatabase[imsi].rand_num;

}
