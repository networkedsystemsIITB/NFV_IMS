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
#include "telecom.h"
#include "uecontext.h"
#include <sys/epoll.h>


#define MAX_THREADS 3 // This constant defines number of threads used by SCSCF

struct arg{
	int id;
	int coreno;
};
struct arg arguments[MAX_THREADS]; 

pthread_t servers[MAX_THREADS]; // Threads 

mutex listen_lock; // This lock will serve for locking socket


int ran_listen_fd; 	

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
  
  //exit(EXIT_FAILURE); 
}

void * run(void* arg1)
{
	int ran_accept_fd; 	
	int shouldbeZero;		
	int returnval; 

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
		1		:	Packet from ICSCF, take action based on SIP header. Send it to HSS
		2		:	Connection to HSS established, 
					send packet to HSS, wait for reply (goto 3)
	 	3		:	Received packet from HSS, process it based on SIP header and send to ICSCF, 
	 				close hss connection, wait for next request from ICSCF (goto 1)
	*/		

	// File descriptor for Epoll
	int epollfd,cur_fd; 

	//Variable to store act_type
	int act_type;

	//Epoll variables to handle events
	struct epoll_event new_file_descriptor_to_watch;
	struct epoll_event current_event;
	struct epoll_event *events_received;

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

	int firstPrintInWhile= 0; // Fpr printing
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
					act_type = fddata.act;					//Action to be performed

					switch(act_type)
					{
						case 1: // Packet received from I-CSCF
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
									TRACE(cout<<"Sent SCSCF-HSS "<<fddata.sipheader<<endl;)
								if(returnval <= 0)
									handle_error("Error occured while trying to write to HSS\n");
					
								new_file_descriptor_to_watch.data.fd = cur_fd;
								new_file_descriptor_to_watch.events = EPOLLIN; // Wait for reply

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
							//Here Addresses sent are not utilized, sent respond to ICSCF 
							handlecase3(epollfd,cur_fd,fdmap,fddata,ICSCFADDR,ICSCFPORTNO,new_file_descriptor_to_watch);
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


	//Structure variable storing S-CSCF server address
	struct sockaddr_in scscf_server_addr;
	//Initialize S-CSCF Address
	bzero((char *) &scscf_server_addr, sizeof(scscf_server_addr)); // Set it to zero
	scscf_server_addr.sin_family = AF_INET;												// Address family = Internet
	scscf_server_addr.sin_addr.s_addr = inet_addr(SCSCFADDR);			//Get IP address of S-CSCF from common.h	
	scscf_server_addr.sin_port = htons(SCSCFPORTNO);							//Get port number of S-CSCF from common.h

	ran_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0); // Create NON blocking socket for listening

	if(ran_listen_fd == -1) // Error occured in socket creation
	{
			handle_error("S-CSCF is not able to create new socket for listening\n");
	}
	

	if(bind(ran_listen_fd, (struct sockaddr *) &scscf_server_addr, sizeof(scscf_server_addr)) == -1) // Bind
	{
			handle_error("S-CSCF is not able to bind socket for listening\n");
	}

	if(listen(ran_listen_fd, MAXCONN) == -1) // If listen failed give error
	{
			handle_error("S-CSCF is not able to listen\n");
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
This function processes the incoming message from ICSCF based on whether incoming request is for registration,deregistration or authentication.
Then forwards the message to HSS .
Parameters
cur_fd : Current file descriptor on which event was received.
epollfd : Used for adding new epoll events
ServerAddress,port : HSS address and Port address is sent
fdmap,fddata
	fddata variable stores various connection variables and context of connection.
	This data is is stored in fdmap and indexed using socket identifier.
*/
int handleRegistrationRequest(int epollfd,int cur_fd, map<int, mdata> &fdmap, mdata &fddata,  char * ServerAddress, int port, epoll_event &new_file_descriptor_to_watch)
{
		Packet pkt;
		char * dataptr; // Pointer to data for copying to packet
		char data[BUF_SIZE]; // To store received packet data
		uint64_t imsi,scscid=1001; // scscid=1001 is send to HSS, so that it can identify message was from SCSCF
		int packet_length;
		int returnval; 
		pkt.clear_pkt();
		bool res; // To store result of HMAC check
		int hss_fd; // File descriptor of HSS		
		struct sockaddr_in hss_server_addr; // Server address of HSS
		UEcontext current_context; // Stores current UEContext	

		returnval = read(cur_fd, data, BUF_SIZE);	//Read packet length

		if(returnval == 0) // This means connection closed at other end
			{
				close(cur_fd);
				fdmap.erase(cur_fd);		
				return 0;
			}
			else if(returnval < 0)
			{
				handle_error("Error occured at SCSCF while trying to read packet lengthfrom ICSCF in Register");
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

					TRACE(cout<<"Packet read "<<returnval<<" bytes instead of "<<packet_length<<" bytes"<<endl;)

					pkt.extract_sip_hdr();
					
					if (HMAC_ON) { // Check HMACP
					res = g_integrity.hmac_check(pkt, 0);
					if (res == false) 
						{
						TRACE(cout << "icscf->scscf:" << " hmac failure: " << endl;)
						g_utils.handle_type1_error(-1, "hmac failure: icscf->scscf:");
						}		
					} 
					if (ENC_ON) {
						g_crypt.dec(pkt, 0);
					} 	

					pkt.extract_item(imsi);
																
					TRACE(cout<<"ICSCF->SCSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)

					fddata.sipheader = pkt.sip_hdr.msg_type;
					/*
					pkt.sip_hdr.msg_type = 1 means it is registration request
					pkt.sip_hdr.msg_type = 2 means it is authentication request
					pkt.sip_hdr.msg_type = 3 means it is de-registration request
					*/
					switch(fddata.sipheader)
					{
						case 1:
						current_context.imsi = imsi;
						pkt.extract_item(current_context.instanceid);
						pkt.extract_item(current_context.expiration_value);
						pkt.extract_item(current_context.integrity_protected);
						TRACE(cout<<current_context.instanceid<<" "<<current_context.expiration_value<<" "<<current_context.integrity_protected<<endl;)
						current_context.gruu = g_telecom.get_gruu(current_context.imsi,current_context.instanceid);
						uecontextmap_lock.lock();
						uecontextmap[imsi] = current_context;
						uecontextmap_lock.unlock();	
						TRACE(cout<<"IMSI "<<imsi<<"GRUU "<<current_context.gruu<<endl;)

						break;
						case 2:
						uecontextmap_lock.lock();
						current_context = uecontextmap[imsi];
						uecontextmap_lock.unlock();	

						pkt.extract_item(current_context.instanceid);
						pkt.extract_item(current_context.expiration_value);
						pkt.extract_item(current_context.integrity_protected);						
						pkt.extract_item(current_context.res);

						if(current_context.res == current_context.xres)
						{
							TRACE(cout <<imsi << " Authentication successful" << endl;)
							current_context.registered = 1;
						}
						else
						{
							cout <<imsi << " Authentication failed" << endl;
							current_context.registered = 0;
						}

						uecontextmap_lock.lock();
						uecontextmap[imsi] = current_context;
						uecontextmap_lock.unlock();		
											
						break;				

						case 3:
						uecontextmap_lock.lock();
						current_context = uecontextmap[imsi];
						uecontextmap_lock.unlock();	

						pkt.extract_item(current_context.instanceid);
						pkt.extract_item(current_context.expiration_value);
						pkt.extract_item(current_context.integrity_protected);						

						if(current_context.expiration_value == 0)
						{
							TRACE(cout <<imsi << " Deregistration request started " << endl;)
						}
						else
						{
							cout <<imsi << " Deregistration request failed?" << endl;
						}

						uecontextmap_lock.lock();
						uecontextmap[imsi] = current_context;
						uecontextmap_lock.unlock();		

						break;
					}


					pkt.clear_pkt();
					pkt.append_item(imsi); 
					pkt.append_item(scscid); // Sending scscid = 1001 

					switch(fddata.sipheader)
					{
						case 1:
						break;
						case 2:					
						pkt.append_item(current_context.registered);						
						break;
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
					
					hss_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0); // Create NON blocking socket for HSS

					if(hss_fd == -1) // Error occured in socket creation
					{
							handle_error("S-CSCF is not able to create new socket for connecting to HSS\n");
					}
					
					bzero((char *) &hss_server_addr, sizeof(hss_server_addr)); // Initialize I-CSCF address
					hss_server_addr.sin_family = AF_INET;
					hss_server_addr.sin_addr.s_addr = inet_addr(ServerAddress);
					hss_server_addr.sin_port = htons(port);
					
					returnval = connect(hss_fd, (struct sockaddr*)&hss_server_addr, sizeof(hss_server_addr));
					
					if((returnval == -1 )&& (errno == EINPROGRESS)) //Connect request in progress
					{
						new_file_descriptor_to_watch.data.fd = hss_fd;
						new_file_descriptor_to_watch.events = EPOLLOUT; // Wait for connect to be successful

						returnval = epoll_ctl(epollfd, EPOLL_CTL_ADD, hss_fd, &new_file_descriptor_to_watch);
						if(returnval == -1)
						{ 
								handle_error("Error in epoll_ctl on Accept");
						}

						fdmap.erase(cur_fd); // Remove current fd data from fdmap
						fddata.act = 2; // Change action to 2
						fddata.initial_fd = cur_fd; // Save file descriptor from which you received request
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
					//Connection successful , write immediately
					returnval = write(hss_fd, pkt.data, pkt.len);

					if(returnval > 0)
						TRACE(cout<<"Sent SCSCF-HSS "<<fddata.sipheader<<endl;)
					if(returnval <= 0)
						handle_error("Error occured while trying to write to HSS\n");
		
					new_file_descriptor_to_watch.data.fd = hss_fd;
					new_file_descriptor_to_watch.events = EPOLLIN; // Wait for HSS to reply

					returnval = epoll_ctl(epollfd, EPOLL_CTL_MOD, hss_fd, &new_file_descriptor_to_watch);

					fdmap.erase(cur_fd);	
					fddata.act = 3;
					fddata.initial_fd = cur_fd;						//Save file descriptor from where connection was received
					fddata.buflen = 0;
					memset(fddata.buf,0,mdata_BUF_SIZE);
					fdmap.insert(make_pair(hss_fd,fddata));
					}
			}												 
}

/*
This function processes the incoming message from HSS based on whether incoming request is for registration,deregistration or authentication.
Then forwards the message to I-CSCF .
Parameters
cur_fd : Current file descriptor on which event was received.
epollfd : Used for adding new epoll events
ServerAddress,port : Not used
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
		int icscf_fd; // Stores ICSCF file descriptor
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
				handle_error("Error occured at SCSCF while trying to read packet lengthfrom HSS");
			}
			else
			{
				//Get I-CSCF file descriptor and close socket
				icscf_fd = fddata.initial_fd;
				fdmap.erase(cur_fd);
				returnval = epoll_ctl(epollfd, EPOLL_CTL_DEL, cur_fd, &new_file_descriptor_to_watch); // Work of FD done, remove it

				close(cur_fd);				
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
				
				uecontextmap_lock.lock();
				current_context = uecontextmap[imsi];
				uecontextmap_lock.unlock();

				TRACE(cout<<"SCSCF->ICSCF "<<imsi<<" "<<pkt.sip_hdr.msg_type<<endl;)

				fddata.sipheader = pkt.sip_hdr.msg_type;
				/*
				pkt.sip_hdr.msg_type = 1 means it is registration request
				pkt.sip_hdr.msg_type = 2 means it is authentication request
				pkt.sip_hdr.msg_type = 3 means it is de-registration request
				*/
					
				switch(fddata.sipheader)
				{
					case 1:// Case 1, got authentication challenge from HSS
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
					TRACE(cout<<imsi<<"is "<<status<<endl;)
					break;
					case 3:
					pkt.extract_item(current_context.registered);
					if(current_context.registered == 0)
					{
						TRACE(cout<<imsi<<"has been deregistered successfully\n";)
						uecontextmap_lock.lock();
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
					case 1:// Case 1, sending authentication challenge from SCSCF to ICSCF
					pkt.append_item(current_context.autn_num);
					pkt.append_item(current_context.rand_num);
					pkt.append_item(current_context.xres);
					pkt.append_item(current_context.k_asme);
					break;

					case 2: // sending registration status back to ICSCF
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
					


				returnval = write(icscf_fd, pkt.data, pkt.len);

				if(returnval > 0)
						TRACE(cout<<"Sent SCSCF-ICSCF"<<fddata.sipheader<<endl;)
				if(returnval <= 0)
						handle_error("Error occured while trying to write to ICSCF\n");
				
				close(icscf_fd);
				}		
}