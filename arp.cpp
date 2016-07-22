#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<pcap.h>
#include <sys/ioctl.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <net/if.h> 
#include <arpa/inet.h> 
#include <net/ethernet.h> 
#include <netinet/if_ether.h> 





int sendarp_req(pcap_t *descr, const char* req_victim_ip, const char* req_attacker_ip,  const char* req_victim_mac,  const char* req_attacker_mac)
 {
	//arp_request 함수입니다

     struct ether_header header;
     header.ether_type=htons(ETH_P_ARP);
	// 헤더의 이더넷 타입은 ARP라고 지정
     struct ether_arp packet;
     packet.arp_hrd=htons(ARPHRD_ETHER);
     packet.arp_pro=htons(ETH_P_IP);
     packet.arp_hln=ETHER_ADDR_LEN;
     packet.arp_pln=sizeof(in_addr_t);
     packet.arp_op=htons(ARPOP_REQUEST);
	//패킷에 대한 정보를 저장하는 구조체입니다 해당 구조체를 통하여 패킷을 정의 할 수 있습니다

     struct in_addr victim_ip_addr={0};

     if (!inet_aton(req_victim_ip,&victim_ip_addr)) {
        printf("%s is not a valid IP address",req_victim_ip);
        exit(1);
     }
	

     memcpy(&packet.arp_tpa,&victim_ip_addr.s_addr,sizeof(packet.arp_tpa));

     struct in_addr attacker_ip_addr={0};

     if (!inet_aton(req_attacker_ip,&attacker_ip_addr)) {
        printf("%s is not a valid IP address",req_attacker_ip);
        exit(1);
     }


     memcpy(&packet.arp_spa,&attacker_ip_addr.s_addr,sizeof(packet.arp_spa));
     memcpy(header.ether_dhost,req_victim_mac,sizeof(header.ether_dhost));
     memcpy(header.ether_shost,req_attacker_mac,sizeof(header.ether_shost));
     memcpy(&packet.arp_sha,req_attacker_mac,sizeof(packet.arp_sha));
     memcpy(&packet.arp_tha,req_victim_mac,sizeof(packet.arp_tha));
	// 메모리에 받은 패킷을 저장하고 있습니다

     unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
     memcpy(frame,&header,sizeof(struct ether_header));
     memcpy(frame+sizeof(struct ether_header),&packet,sizeof(struct ether_arp));


     if (pcap_inject(descr,frame,sizeof(frame))==-1) {
	//메모리에 저장 시킨 패킷을 전송하는 부분 입니다
         pcap_perror(descr,0);
         pcap_close(descr);
         exit(1);
     }
 }


int main(int argc, char * argv[]){
	
	FILE * fp;
	char buf[512];
	char my_ip[2][512];
	int i =0;
	char gate[2][512];
	char victim[2][512];
	char *dev, errbuf[PCAP_ERRBUF_SIZE];  
	dev = pcap_lookupdev(errbuf); 
	const char * test[6];
	bpf_u_int32 netaddr=0, mask=0;  
	struct bpf_program filter;   
	pcap_t *descr = NULL;    
	struct pcap_pkthdr pkthdr;  
	const unsigned char *packet=NULL; 
	
		
	



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
			//어디까지를 파싱해야하는지에 대한 부분을 정확하게는 구현 하지 못해서 일단은 갯수로 받아 왔습니다 	
			//이 부분도 조금 더 생각 해보겠습니다
			printf("attacker_HW : %s\n",my_ip[1]);
			i++;			
		}

		if(strstr(buf,"inet addr") != 0){
		//ip역시 맥 주소와 같은 방식으로 파싱을 시작 했습니다.
                        strncpy(my_ip[1],strstr(buf,"192"),14);
                        printf("attacker_ip : %s\n",my_ip[0]);
			i++;
                }
		
		if(i == 2){
		//ip와 맥 주소를 정상적으로 파싱했을 경우 더이상 파일을 읽지 않습니다
			i=0;
			break;
		}
	}

	system("route > aaa.txt");
	//라우터에 대한 결과 역시 같은 텍스트 파일에 저장하여 그 결과를 가져오고 있습니다.	

	fp = fopen("aaa.txt","r");

	while(!feof(fp)){
		
		
                fgets(buf,512,fp);
		
		if(strstr(buf,"192") != 0){
			//같은 방식으로 게이트웨이의 ip값을 파싱했습니다
                        strncpy(gate[0],strstr(buf,"192"),14);
                        printf("gateway_ip : %s\n",gate[0]);
                        i++;
                }

		if(i != 0)
			break;
	}
	
	system("rm aaa.txt");
	//ip값들과 자신의 맥주소를 모두 긁어 오게 되면 민감한 정보가 저장된 aaa.txt파일을 제거 하겠습니다
	dev = pcap_lookupdev(errbuf);	
	//전송할 디바이스를 선택합니다   	



	if ((descr = pcap_open_live(dev, 65536, 0,  512, errbuf))==NULL) 
	{ 
		printf("ERROR: %s\n", errbuf); 
   		exit(1); 
  	} 	

	for(int i = 0 ;i <6;i++)
	test[i] = "0xff";
	//test는 아직 존재하지 않는 맥주소를 위한 부분 입니다

	sendarp_req(descr, argv[1],my_ip[0], test,my_ip[1]);
	//arp_request를 시작 합니다
}





























