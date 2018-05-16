#include "ran.h"
#include "common.h"

RanContext::RanContext() // Initialize RAN context
 {
	emm_state = 0; 
	imsi = 0; 
	gruu = 0; 
	ip_addr = UEADDR;
	instanceid = 1;

	key = 0; 
	k_asme = 0; 
	ksi_asme = 7; 
	k_nas_enc = 0; 
	k_nas_int = 0; 
	nas_enc_algo = 0; 
	nas_int_algo = 0; 

	user_server = 0;
	user_client = 0;
	pcscf_server = PCSCFPORTNO;
	pcscf_client= 0;

	expiration_time = 1;

	mcc = 1; 
	mnc = 1; 
	plmn_id = g_telecom.get_plmn_id(mcc, mnc);
	msisdn = 0; 
}

void RanContext::init(uint32_t arg) { // Initialize RAN context
	privateidentity =(int) arg;
	key = arg; 	
	msisdn = 9000000000 + arg;
	imsi = g_telecom.get_imsi(plmn_id, msisdn);
	expiration_value = 1;
	user_server = 6000 + arg;
}
RanContext::~RanContext() {

}

void Ran::init(int arg) {
	ran_ctx.init(arg);
}

int Ran::conn_pcscf() {
	pcscf_client.conn(PCSCFADDR,PCSCFPORTNO);
}

/*
This method simulates register procedure. 
It sends IMSI and other parameters to P-CSCF for registration and retrieves authentication challenge.
*/

void Ran::register1() { 
	uint64_t imsi;
	bool res;

	pkt.clear_pkt(); // clear packet
	pkt.append_item(ran_ctx.imsi); //append IMSI
	pkt.append_item(ran_ctx.instanceid);
	pkt.append_item(ran_ctx.expiration_value);
	TRACE(cout<<ran_ctx.instanceid<<" "<<ran_ctx.expiration_value<<endl;)
	imsi = ran_ctx.imsi;
	
	TRACE(cout<<"Registration process for "<<ran_ctx.imsi <<" started"<<endl;)

	pkt.prepend_sip_hdr(1); // Flag == 1 indiacates registration request
	
	pcscf_client.snd(pkt); // send packet
	
	pkt.clear_pkt();

	pcscf_client.rcv(pkt); // receive packet
	
	pkt.extract_sip_hdr();

	pkt.extract_item(ran_ctx.imsi); // IMSI received
	pkt.extract_item(ran_ctx.xautn_num);
	pkt.extract_item(ran_ctx.rand_num); // Received Authentication information
	pkt.extract_item(ran_ctx.k_asme);
	//ERROR CHECKING
	assert(imsi == ran_ctx.imsi);
	assert(pkt.sip_hdr.msg_type == 1); 
	
	TRACE(cout<<"Message from PCSCF for "<<ran_ctx.imsi<<endl;)		
			
	ran_ctx.sqn = ran_ctx.rand_num + 1;
	ran_ctx.res = ran_ctx.key + ran_ctx.sqn + ran_ctx.rand_num;
	ran_ctx.autn_num = ran_ctx.res + 1;	

	if (ran_ctx.autn_num != ran_ctx.xautn_num) {
		cout << "register1:" << " authentication of SCSCF failure: " << ran_ctx.imsi << " "<<ran_ctx.autn_num<<" "<<ran_ctx.xautn_num<<" "<<ran_ctx.res<<" "<<ran_ctx.key<<" "<<ran_ctx.rand_num<<endl;
		exit(1);
	}
}
/*
This method simulates authentication procedure. 
It sends reply to authentication challenge send by P-CSCF in register.
It checks whether authentication was successful or not.
It does not return anything. Return value is ignored.
*/
bool Ran::authenticate()
{

	uint64_t imsi;
	bool res;
	string status;

	pkt.clear_pkt(); // clear packet
	pkt.append_item(ran_ctx.imsi); //append IMSI
	pkt.append_item(ran_ctx.instanceid);
	pkt.append_item(ran_ctx.expiration_value);	
	pkt.append_item(ran_ctx.res);	
	imsi = ran_ctx.imsi;

	if (ENC_ON) // Add encryption
	{
		g_crypt.enc(pkt,0); 
	}
	if (HMAC_ON)  // Add HMAC
	{
		g_integrity.add_hmac(pkt, 0);
	} 	
	TRACE(cout<<"authenticate process for "<<ran_ctx.imsi <<" started"<<endl;)
	TRACE(cout<<imsi<<" sent Res "<<ran_ctx.res<<"\n";)

	pkt.prepend_sip_hdr(2); // Flag == 2 indiacates authenticate request
	



	pcscf_client.snd(pkt); // send packet
	
	pkt.clear_pkt();

	pcscf_client.rcv(pkt); // receive packet
	
	pkt.extract_sip_hdr();

	if (HMAC_ON) { // Check HMACP
		res = g_integrity.hmac_check(pkt, 0);
		if (res == false) 
		{
			TRACE(cout << "ransim->pcscf:" << " hmac failure: " << endl;)
			g_utils.handle_type1_error(-1, "hmac failure: ransim->pcscf");
		}		
	} 
	if (ENC_ON) {
		g_crypt.dec(pkt, 0);
	} 	


	pkt.extract_item(ran_ctx.imsi); // IMSI received
	pkt.extract_item(status);// Status of Authentication received

	//ERROR CHECKING
	assert(imsi == ran_ctx.imsi);
	assert(pkt.sip_hdr.msg_type == 2); 
	
	TRACE(cout<<"Message from PCSCF for "<<imsi<<" "<<status<<endl;)				
}
/*
This method simulates deregistration procedure. 
It does not return anything. Return value is ignored.
*/

bool Ran::deregsiter()
{
	uint64_t imsi;
	bool res;
	uint64_t registered;
	pkt.clear_pkt(); // clear packet
	pkt.append_item(ran_ctx.imsi); //append IMSI
	pkt.append_item(ran_ctx.instanceid);
	ran_ctx.expiration_value = 0; // Deregistration process is identified by 0 expiration value
	pkt.append_item(ran_ctx.expiration_value);	

	imsi = ran_ctx.imsi;

	if (ENC_ON) // Add encryption
	{
		g_crypt.enc(pkt,0); 
	}
	if (HMAC_ON)  // Add HMAC
	{
		g_integrity.add_hmac(pkt, 0);
	} 	
	TRACE(cout<<"deregsiter process for "<<ran_ctx.imsi <<" started"<<endl;)

	pkt.prepend_sip_hdr(3); // Flag == 2 indiacates authenticate request
	



	pcscf_client.snd(pkt); // send packet
	
	pkt.clear_pkt();

	pcscf_client.rcv(pkt); // receive packet
	
	pkt.extract_sip_hdr();

	if (HMAC_ON) { // Check HMACP
		res = g_integrity.hmac_check(pkt, 0);
		if (res == false) 
		{
			TRACE(cout << "ransim->pcscf:" << " hmac failure: " << endl;)
			g_utils.handle_type1_error(-1, "hmac failure: ransim->pcscf");
		}		
	} 
	if (ENC_ON) {
		g_crypt.dec(pkt, 0);
	} 	


	pkt.extract_item(ran_ctx.imsi); // IMSI received
	pkt.extract_item(registered);// 

	//ERROR CHECKING
	assert(imsi == ran_ctx.imsi);
	assert(pkt.sip_hdr.msg_type == 3); 
	if(registered == 0)
	{
		TRACE(cout<<imsi<<" has been deregistered\n";)
	}
	else
	{
		cout<<imsi<<" There is issue in deregistration\n";
	}
}	
