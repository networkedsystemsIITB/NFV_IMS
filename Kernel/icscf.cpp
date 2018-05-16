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
#include "security.h"
#include "uecontext.h"
#include <sys/epoll.h>
#include <assert.h>


#define MAX_THREADS 3 // This constant defines number of threads used by ICSCF

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
	int ran_accept_fd; 	
	int shouldbeZero;		// Storing error
	int returnval; // For storing return values of functions

	/*
	fddata variable stores various connection variables and context of connection.
	*/	
	struct mdata fddata;
	map<int, mdata> fdmap;
	/*FDMAP 
		key : file descriptor whose state needs to be maintained
		value: mdata - state type ("act"), and corresponding required information
	 	
	 	Action type(act) and corresponding action to be taken
		Value	:	Current State and/or Action Required
		1		:	Packet from PCSCF, take action based on SIP header. Send it to HSS		
		2		:	Connection to HSS established, 
					send packet to HSS, wait for reply (goto 3)
	 	3		:	Received packet from HSS, process it based on SIP header and send to SCSCF, 
	 				close connection with HSS.
	 	4		:	Connection to SCSCF established, 
					send packet to SCSCF, wait for reply (goto 3)
	 	5		:	Received packet from SCSCF, process it based on SIP header and send it to PCSCF,	
	 				close SCSCF,PCSCF connection, wait for next request from PCSCF (goto 1)
	*/		

	// File descriptor for Epoll
	int epollfd,cur_fd; 

	//Variable to store act_type
	int act_type;

	//Epoll variables to handle events
	struct epoll_event new_file_descriptor_to_watch; 		// New file descriptor to add to epoll
	struct epoll_event current_event;						// Variable to store event we are currently processing
	struct epoll_event *events_received;					// Stores all events received for processing

	epollfd = epoll_create(MAXEVENTS); // MAXEVENTS is ignored here
	if(epollfd == -1) handle_error("Error in epoll_create");

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
	int number_of_events; // This variable will contain number of events

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

				if(current_event.data.fd == ran_listen_fd) // Got receive 
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
						new_file_descriptor_to_watch.events = EPOLLIN ;//| EPOLLET| EPOLLRDHUP; //priya

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
					act_type = fddata.act;					//Action to be performed

					switch(act_type)
					{
						case 1:
							if(events_received[i].events & EPOLLIN)
							{
								handleRegistrationRequest(epollfd,cur_fd,fdmap,fddata,HSSADDR,HSSPORTNO,new_file_descriptor_to_watch);
							}
							else
							{
								handle_epoll_error("Its not EPOLLIN in case 1");
							}
						break;

						case 2:
							if(events_received[i].events & EPOLLOUT)
							{
								//Connection successful 
								returnval = write(cur_fd, fddata.buf, fddata.buflen);

								if(returnval > 0)
									TRACE(cout<<"Sent ICSCF-HSS "<<fddata.sipheader<<endl;)
								if(returnval <= 0)
									handle_error("Error occured while trying to write to HSS\n");
					
								new_file_descriptor_to_watch.data.fd = cur_fd;
								new_file_descriptor_to_watch.events = EPOLLIN; // Wait for RAN to reply

								returnval = epoll_ctl(epollfd, EPOLL_CTL_MOD, cur_fd, &new_file_descriptor_to_watch);
								fdmap.erase(cur_fd);
								fddata.act = 3;
								fddata.buflen = 0;
								memset(fddata.buf,0,mdata_BUF_SIZE);
								fdmap.insert(make_pair(cur_fd,fddata));								
							}
							else
							{
								handle_epoll_error("Its not epoll out in case 2");
							}
						break;
						case 3:
						if(events_received[i].events & EPOLLIN)
						{
							//Here Addresses sent are not yet utilized
							handlecase3(epollfd,cur_fd,fdmap,fddata,SCSCFADDR,SCSCFPORTNO,new_file_descriptor_to_watch);
						}
						else
						{
							handle_epoll_error("Its not EPOLLIN in case 3");
						}	
						break;		

						case 4:
							if(events_received[i].events & EPOLLOUT)
							{
								//Connection successful 
								returnval = write(cur_fd, fddata.buf, fddata.buflen);

								if(returnval > 0)
									TRACE(cout<<"Sent ICSCF-SCSCF "<<fddata.sipheader<<endl;)
								if(returnval <= 0)
									handle_error("Error occured while trying to write to SCSCF\n");
					
								new_file_descriptor_to_watch.data.fd = cur_fd;
								new_file_descriptor_to_watch.events = EPOLLIN; // Wait for RAN to reply

								returnval = epoll_ctl(epollfd, EPOLL_CTL_MOD, cur_fd, &new_file_descriptor_to_watch);
								fdmap.erase(cur_fd);
								fddata.act = 5;
								fddata.buflen = 0;
								memset(fddata.buf,0,mdata_BUF_SIZE);
								fdmap.insert(make_pair(cur_fd,fddata));								
							}
							else
							{
								handle_epoll_error("Its not epoll out in case 2");
							}
							
						break;

						case 5:
						if(events_received[i].events & EPOLLIN)
						{
							//Here Addresses sent are not yet utilized
							handlecase5(epollfd,cur_fd,fdmap,fddata,ICSCFADDR,ICSCFPORTNO,new_file_descriptor_to_watch);
						}
						else
						{
							handle_epoll_error("Its not EPOLLIN in case 3");
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


	//Structure variable storing P-CSCF server address
	struct sockaddr_in icscf_server_addr;
	//Initialize I-CSCF Address
	bzero((char *) &icscf_server_addr, sizeof(icscf_server_addr)); // Set it to zero
	icscf_server_addr.sin_family = AF_INET;												// Address family = Internet
	icscf_server_addr.sin_addr.s_addr = inet_addr(ICSCFADDR);			//Get IP address of I-CSCF from common.h	
	icscf_server_addr.sin_port = htons(ICSCFPORTNO);							//Get port number of I-CSCF from common.h

	ran_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0); // Create NON blocking socket for listening

	if(ran_listen_fd == -1) // Error occured in socket creation
	{
			handle_error("I-CSCF is not able to create new socket for listening\n");
	}
	

	if(bind(ran_listen_fd, (struct sockaddr *) &icscf_server_addr, sizeof(icscf_server_addr)) == -1) // Bind
	{
			handle_error("I-CSCF is not able to bind socket for listening\n");
	}

	if(listen(ran_listen_fd, MAXCONN) == -1) // If listen failed give error
	{
			handle_error("I-CSCF is not able to listen\n");
	}

	//spawn server threads
	for(int i=0;i<MAX_THREADS;i++){
		arguments[i].coreno = i;
		arguments[i].id = i;
		//arguments[i].myhss = myhss;
		pthread_create(&servers[i],NULL,run,&arguments[i]);
	}


	//Wait for server threads to complete
	for(int i=0;i<MAX_THREADS;i++){
		pthread_join(servers[i],NULL);		
	}

	return 0;
}
/*
This function processes the incoming message from PCSCF based on whether incoming request is for registration,deregistration or authentication.
Then forwards the message to HSS to retrive SCSCF address .
Parameters
cur_fd : Current file descriptor on which event was received.
epollfd : Used for adding new epoll events
ServerAddress,port : Address and port of HSS
fdmap,fddata
	fddata variable stores various connection variables and context of connection.
	This data is is stored in fdmap and indexed using socket identifier.
*/
int handleRegistrationRequest(int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata,  char * ServerAddress, int port, epoll_event &new_file_descriptor_to_watch)
{
		Packet pkt;
		char * dataptr; // Pointer to data for copying to packet
		char data[BUF_SIZE]; // To store received packet data
		uint64_t imsi,icscid=1000; // icscid = 1000 is send , so HSS can identify that incoming request is from I-CSCF
		int packet_length;
		int returnval; 
		pkt.clear_pkt();
		bool res; // To store result of HMAC check
		int hss_fd; // File descriptor of HSS		
		struct sockaddr_in hss_server_addr; // Server address of HSS
		UEcontext current_context; // Stores current UEContext	

		
		epoll_ctl(epollfd, EPOLL_CTL_DEL, cur_fd, &new_file_descriptor_to_watch); // Work of ran FD, remove it

		returnval = read(cur_fd, data, BUF_SIZE);	//Read packet length

		if(returnval == 0) // This means connection closed at other end
			{
				close(cur_fd);
				fdmap.erase(cur_fd);		
				return 0;
			}
			else if(returnval < 0)
			{
				handle_error("Error occured at PCSCF while trying to read packet lengthfrom RAN in Register");
			}
			else
			{
				//memmove(&packet_length, data, sizeof(int) * sizeof(uint8_t)); // Priya Move packet length into packet_len
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

					TRACE(cout<<"Packet read "<<returnval<<" bytes instead of "<<packet_length<<" bytes"<<endl;)

					pkt.extract_sip_hdr();
					
					if (HMAC_ON) { // Check HMACP
					res = g_integrity.hmac_check(pkt, 0);
					if (res == false) 
						{
						TRACE(cout << "pcscf->icscf:" << " hmac failure: " << endl;)
						g_utils.handle_type1_error(-1, "hmac failure: pcscf->icscf:");
						}		
					} 
					if (ENC_ON) {
						g_crypt.dec(pkt, 0);
					} 	

					pkt.extract_item(imsi);
					/*
					pkt.sip_hdr.msg_type = 1 means it is registration request
					pkt.sip_hdr.msg_type = 2 means it is authentication request
					pkt.sip_hdr.msg_type = 3 means it is de-registration request
					*/					
					switch(pkt.sip_hdr.msg_type) // Read packet here
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
						case 2:
						uecontextmap_lock.lock(); // Locks before updating uecontextmap
						current_context = uecontextmap[imsi];
						uecontextmap_lock.unlock();						
						pkt.extract_item(current_context.instanceid);
						pkt.extract_item(current_context.expiration_value);
						pkt.extract_item(current_context.integrity_protected);
						pkt.extract_item(current_context.res);
						uecontextmap_lock.lock(); // Locks before updating uecontextmap
						uecontextmap[imsi]=current_context;
						uecontextmap_lock.unlock();			

						TRACE(cout<<"Received res for "<<imsi<<" "<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<" "<<current_context.res<<endl;)

						break;
						case 3:
						uecontextmap_lock.lock(); // Locks before updating uecontextmap
						current_context = uecontextmap[imsi];
						uecontextmap_lock.unlock();						
						pkt.extract_item(current_context.instanceid);
						pkt.extract_item(current_context.expiration_value);
						pkt.extract_item(current_context.integrity_protected);
						uecontextmap_lock.lock(); // Locks before updating uecontextmap
						uecontextmap[imsi]=current_context;
						uecontextmap_lock.unlock();

						assert(current_context.expiration_value == 0);
						TRACE(cout<<"Received deregistration request for "<<imsi<<endl;)


						break;
					}


																
					TRACE(cout<<"PCSCF->ICSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)

					fddata.sipheader = pkt.sip_hdr.msg_type;
					

					pkt.clear_pkt();
					pkt.append_item(imsi); 
					pkt.append_item(icscid);

					switch(fddata.sipheader)
					{
						case 1:
						pkt.append_item(current_context.instanceid);
						pkt.append_item(current_context.expiration_value);
						pkt.append_item(current_context.integrity_protected);						
						break;
						case 2:
						pkt.append_item(current_context.instanceid);
						pkt.append_item(current_context.expiration_value);
						pkt.append_item(current_context.integrity_protected);							
						case 3:
						pkt.append_item(current_context.instanceid);
						pkt.append_item(current_context.expiration_value);
						pkt.append_item(current_context.integrity_protected);							
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
					
					hss_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0); // Create NON blocking socket for I-CSCF

					if(hss_fd == -1) // Error occured in socket creation
					{
							handle_error("I-CSCF is not able to create new socket for connecting to HSS\n");
					}
					
					bzero((char *) &hss_server_addr, sizeof(hss_server_addr)); // Initialize I-CSCF address
					hss_server_addr.sin_family = AF_INET;
					hss_server_addr.sin_addr.s_addr = inet_addr(ServerAddress);
					hss_server_addr.sin_port = htons(port);
					
					returnval = connect(hss_fd, (struct sockaddr*)&hss_server_addr, sizeof(hss_server_addr));
					
					if((returnval == -1 )&& (errno == EINPROGRESS)) //Connect request in progress
					{
						new_file_descriptor_to_watch.data.fd = hss_fd;
						new_file_descriptor_to_watch.events = EPOLLOUT; // Wait for connection to be successful

						returnval = epoll_ctl(epollfd, EPOLL_CTL_ADD, hss_fd, &new_file_descriptor_to_watch);
						if(returnval == -1)
						{ 
								handle_error("Error in epoll_ctl on Accept");
						}

						fdmap.erase(cur_fd); // Remove current fd data from fdmap
						fddata.act = 2; // Change action to 2
						fddata.initial_fd = cur_fd; // Save PCSCF file descriptor
						memcpy(fddata.buf, pkt.data, pkt.len); //Copy packet data
						fddata.buflen = pkt.len;	//Copy packet length
						fdmap.insert(make_pair(hss_fd,fddata)); //Insert into map
	
					}
					else if(returnval == -1)
					{
						cout<<errno<<endl;
						handle_error("ERROR in connect request\n");
					}
					else
					{
					//Connection successful 
					returnval = write(hss_fd, pkt.data, pkt.len);

					if(returnval > 0)
						TRACE(cout<<"Sent ICSCF-HSS "<<fddata.sipheader<<endl;)
					if(returnval <= 0)
						handle_error("Error occured while trying to write to HSS\n");
		
					new_file_descriptor_to_watch.data.fd = hss_fd;
					new_file_descriptor_to_watch.events = EPOLLIN; // Wait for RAN to reply

					returnval = epoll_ctl(epollfd, EPOLL_CTL_MOD, hss_fd, &new_file_descriptor_to_watch);

					fdmap.erase(cur_fd);	
					fddata.act = 3;
					fddata.initial_fd = cur_fd;
					fddata.buflen = 0;
					memset(fddata.buf,0,mdata_BUF_SIZE);
					fdmap.insert(make_pair(hss_fd,fddata));
					}
			}												 
}
/*
This function processes the incoming message from HSS based on whether incoming request is for registration,deregistration or authentication.
Then forwards the message to SCSCF.
Parameters
cur_fd : Current file descriptor on which event was received.
epollfd : Used for adding new epoll events
ServerAddress,port : Address and port of SCSCF
fdmap,fddata
	fddata variable stores various connection variables and context of connection.
	This data is is stored in fdmap and indexed using socket identifier.
*/
int handlecase3(int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata,  char * ServerAddress, int port, epoll_event &new_file_descriptor_to_watch)
{
		Packet pkt;
		char * dataptr; // Pointer to data for copying to packet
		char data[BUF_SIZE]; // To store received packet data
		uint64_t imsi;
		int packet_length;
		int returnval;
		pkt.clear_pkt();
		bool res; // To store result of HMAC check
		int scscf_fd; // File descriptor of HSS		
		struct sockaddr_in scscf_server_addr; // Server address of SCSCF
		UEcontext current_context; // Stores current UEContext	
		int hssStatus; // Whether retrieval of SCSCF is successful
		
		epoll_ctl(epollfd, EPOLL_CTL_DEL, cur_fd, &new_file_descriptor_to_watch); // Work of HSS FD, remove it

		returnval = read(cur_fd, data, BUF_SIZE);	//Read packet length
		close(cur_fd); // Close HSS socket its job is done

		if(returnval == 0) // This means connection closed at other end
			{
				fdmap.erase(cur_fd);		
				return 0;
			}
			else if(returnval < 0)
			{
				handle_error("Error occured at ICSCF while trying to read packet lengthfrom HSS in Register");
			}
			else
			{
				//memmove(&packet_length, data, sizeof(int) * sizeof(uint8_t)); // Priya Move packet length into packet_len
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

					TRACE(cout<<"Packet read "<<returnval<<" bytes instead of "<<packet_length<<" bytes"<<endl;)

					pkt.extract_sip_hdr();
					
					if (HMAC_ON) { // Check HMACP
					res = g_integrity.hmac_check(pkt, 0);
					if (res == false) 
						{
						TRACE(cout << "HSS->ICSCF:" << " hmac failure: " << endl;)
						g_utils.handle_type1_error(-1, "hmac failure: HSS->ICSCF:");
						}		
					} 
					if (ENC_ON) {
						g_crypt.dec(pkt, 0);
					} 	

					pkt.extract_item(imsi);
																
					TRACE(cout<<"HSS->ICSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)

					fddata.sipheader = pkt.sip_hdr.msg_type;

					/*
					pkt.sip_hdr.msg_type = 1 means it is registration request
					pkt.sip_hdr.msg_type = 2 means it is authentication request
					pkt.sip_hdr.msg_type = 3 means it is de-registration request
					*/					

					switch(pkt.sip_hdr.msg_type) // Read packet here
					{
						case 1:
						case 2:
						case 3:
						
						uecontextmap_lock.lock();
						current_context = uecontextmap[imsi];
						uecontextmap_lock.unlock();
						assert(current_context.imsi == imsi); 
						pkt.extract_item(hssStatus);
						pkt.extract_item(current_context.scscf_addr);
						pkt.extract_item(current_context.scscf_port);

						if(hssStatus == 0) cout<<"Get scscf failed ";
						else TRACE(cout<<"Get scscf successful ";)
						TRACE(cout<<"IMSI "<<imsi<<" "<<current_context.scscf_addr<<" "<<current_context.scscf_port<<endl;)
						
						uecontextmap_lock.lock(); // Locks before updating uecontextmap
						uecontextmap[imsi]=current_context;
						uecontextmap_lock.unlock();				
								
						break;
					}
					pkt.clear_pkt();
					pkt.append_item(imsi); 

					switch(fddata.sipheader) 
					{
						case 1:
						pkt.append_item(current_context.instanceid);
						pkt.append_item(current_context.expiration_value);
						pkt.append_item(current_context.integrity_protected);
						TRACE(cout<<"sending to scscf for reg"<<current_context.instanceid<<endl;)						
						break;
						case 2:
						pkt.append_item(current_context.instanceid);
						pkt.append_item(current_context.expiration_value);
						pkt.append_item(current_context.integrity_protected);
						pkt.append_item(current_context.res);
						TRACE(cout<<"Sending to SCSCF for auth"<<current_context.instanceid<<"res "<<current_context.res<<endl;)						
						case 3:
						pkt.append_item(current_context.instanceid);
						pkt.append_item(current_context.expiration_value);
						pkt.append_item(current_context.integrity_protected);
						TRACE(cout<<"Sending to SCSCF for deregistration"<<current_context.instanceid<<"expiration_value "<<current_context.expiration_value<<endl;)						

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
					
					scscf_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0); // Create NON blocking socket for I-CSCF

					if(scscf_fd == -1) // Error occured in socket creation
					{
							handle_error("I-CSCF is not able to create new socket for connecting to S-CSCF\n");
					}
					
					bzero((char *) &scscf_server_addr, sizeof(scscf_server_addr)); // Initialize I-CSCF address
					scscf_server_addr.sin_family = AF_INET;
					scscf_server_addr.sin_addr.s_addr = inet_addr(ServerAddress);
					scscf_server_addr.sin_port = htons(port);
					
					returnval = connect(scscf_fd, (struct sockaddr*)&scscf_server_addr, sizeof(scscf_server_addr));
					
					if((returnval == -1 )&& (errno == EINPROGRESS)) //Connect request in progress
					{
						new_file_descriptor_to_watch.data.fd = scscf_fd;
						new_file_descriptor_to_watch.events = EPOLLOUT; // Wait for RAN to close the connection

						returnval = epoll_ctl(epollfd, EPOLL_CTL_ADD, scscf_fd, &new_file_descriptor_to_watch);
						if(returnval == -1)
						{ 
								handle_error("Error in epoll_ctl on Accept");
						}

						fdmap.erase(cur_fd); // Remove current fd data from fdmap
						fddata.act = 4; // Change action to 4
						memcpy(fddata.buf, pkt.data, pkt.len); //Copy packet data
						fddata.buflen = pkt.len;	//Copy packet length
						fdmap.insert(make_pair(scscf_fd,fddata)); //Insert into map
	
					}
					else if(returnval == -1)
					{
						cout<<errno<<endl;
						handle_error("ERROR in connect request\n");
					}
					else
					{
					//Connection successful 
					returnval = write(scscf_fd, pkt.data, pkt.len);

					if(returnval > 0)
						TRACE(cout<<"Sent ICSCF-SCSCF "<<fddata.sipheader<<endl;)
					if(returnval <= 0)
						handle_error("Error occured while trying to write to SCSCF\n");
		
					new_file_descriptor_to_watch.data.fd = scscf_fd;
					new_file_descriptor_to_watch.events = EPOLLIN; // Wait for SCSCF to reply

					returnval = epoll_ctl(epollfd, EPOLL_CTL_ADD, scscf_fd, &new_file_descriptor_to_watch);

					fdmap.erase(cur_fd);	
					fddata.act = 5;
					fddata.buflen = 0;
					memset(fddata.buf,0,mdata_BUF_SIZE);
					fdmap.insert(make_pair(scscf_fd,fddata));
					}
			}
}
/*
This function processes the incoming message from SCSCF based on whether incoming request is for registration,deregistration or authentication.
Then forwards the message to PCSCF address from where initial request was received.
Parameters
cur_fd : Current file descriptor on which event was received.
epollfd : Used for adding new epoll events
ServerAddress,port : Not used
	fddata variable stores various connection variables and context of connection.
	This data is is stored in fdmap and indexed using socket identifier.
*/
int handlecase5(int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata,  char * ServerAddress, int port, epoll_event &new_file_descriptor_to_watch)
{
		Packet pkt;
		char * dataptr; // Pointer to data for copying to packet
		char data[BUF_SIZE]; // To store received packet data
		uint64_t imsi;
		int packet_length;
		int returnval; 
		pkt.clear_pkt();
		bool res; // To store result of HMAC check
		int pcscf_fd; // Stores ran file descriptor
		UEcontext current_context; // Stores current UEContext	
		string status;
	
		returnval = read(cur_fd, data, BUF_SIZE);	//Read packet length

		if(returnval == 0) // This means connection closed at other end
			{
				close(cur_fd);
				//close(fddata.initial_fd);
				fdmap.erase(cur_fd);		
				return 0;
			}
			else if(returnval < 0)
			{
				handle_error("Error occured at PCSCF while trying to read packet lengthfrom RAN in Register");
			}
			else
			{
				//Get P-CSCF file descriptor and close socket
				pcscf_fd = fddata.initial_fd;
				fdmap.erase(cur_fd);
				returnval = epoll_ctl(epollfd, EPOLL_CTL_DEL, cur_fd, &new_file_descriptor_to_watch); // Work of FD done, remove it

				close(cur_fd);				
				//memmove(&packet_length, data, sizeof(int) * sizeof(uint8_t)); // Priya Move packet length into packet_len
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

				TRACE(cout<<"Packet read "<<packet_length<<" bytes\n";)

				pkt.extract_sip_hdr();
					
				if (HMAC_ON) { // Check HMACP
					res = g_integrity.hmac_check(pkt, 0);
					if (res == false) 
						{
						TRACE(cout << "hss->icscf:" << " hmac failure: " << endl;)
						g_utils.handle_type1_error(-1, "hmac failure: hss->icscf:");
						}		
					} 
				if (ENC_ON) {
						g_crypt.dec(pkt, 0);
					} 	

				pkt.extract_item(imsi);
																
				TRACE(cout<<"SCSCF->ICSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)

				fddata.sipheader = pkt.sip_hdr.msg_type;
					
				switch(fddata.sipheader)
				{
					case 1:// Received Authentication data from SCSCF
					uecontextmap_lock.lock();
					current_context = uecontextmap[imsi];
					uecontextmap_lock.unlock();					
					pkt.extract_item(current_context.autn_num);
					pkt.extract_item(current_context.rand_num);
					pkt.extract_item(current_context.xres);
					pkt.extract_item(current_context.k_asme);
					TRACE(cout<<"Managed to get authorization stuff"<<current_context.autn_num<<" "<<current_context.rand_num<<" "<<current_context.xres<<" "<<current_context.k_asme<<endl;)
					uecontextmap_lock.lock();
					uecontextmap[imsi] = current_context;
					uecontextmap_lock.unlock();					
					break;
					case 2:
					pkt.extract_item(status);
					TRACE(cout<<imsi<<"is "<<status;)
					break;
					case 3:
					pkt.extract_item(current_context.registered);
					if(current_context.registered == 0)
					{
						TRACE(cout<<imsi<<"has been deregistered successfully\n";)
						uecontextmap_lock.lock();
						/*if(uecontextmap.find(imsi) != uecontextmap.end())
						{
							uecontextmap.erase(imsi);
						}
						else
						{
							cout<<"Unable to find "<<imsi<<" in map"<<endl;
						}*/
						if(uecontextmap.erase(imsi) ==0) cout<<"Unable to find "<<imsi<<" in map"<<endl;
							
						uecontextmap_lock.unlock();						
					}
					else
					{
						cout<<"ERROR in deregistration\n";
					}				
					break;
				}

				pkt.clear_pkt();
				pkt.append_item(imsi); 

				switch(fddata.sipheader)
				{
					case 1:// Case 1, sending authentication challenge from SCSCF => ICSCF =>PCSCF
					pkt.append_item(current_context.autn_num);
					pkt.append_item(current_context.rand_num);
					pkt.append_item(current_context.xres);
					pkt.append_item(current_context.k_asme);
					pkt.append_item(current_context.scscf_addr);
					pkt.append_item(current_context.scscf_port);
					break;

					case 2:
					pkt.append_item(status);
					break;

					case 3:
					pkt.append_item(current_context.registered);
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
					


				returnval = write(pcscf_fd, pkt.data, pkt.len);

				if(returnval > 0)
						TRACE(cout<<"Sent ICSCF-PCSCF"<<fddata.sipheader<<endl;)
				if(returnval <= 0)
						handle_error("Error occured while trying to write to PCSCF\n");
				
				close(pcscf_fd); // close it outside from here in case of error
				}		
}