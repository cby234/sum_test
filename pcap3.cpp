#include"stdafx.h"
#include"pcap.h"
#include<WinSock2.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *h, const u_char *data);
//패킷을 무한 루프 상태에서 읽고 처리하는 함수

typedef struct Ethernet_Header//이더넷 헤더 구조체
{
	u_char des[6];//수신자 MAC 주소
	u_char src[6];//송신자 MAC 주소
	short int ptype;//뒤에 나올 패킷의 프로토콜 종류(예:ARP/IP/RARP)
			//IP 헤더가 오는 경우 : 0x0800
			//ARP 헤더가 오는 경우 : 0x0806
			//RARP 헤더가 오는 경우 : 0x0835
}Ethernet_Header;


typedef struct ipaddress
{
	u_char ip1;
	u_char ip2;
	u_char ip3;
	u_char ip4;
}ip;

//IP 프로토콜의 헤더를 저장할 구조체 정의
typedef struct IPHeader
{
	u_char HeaderLength : 4;//헤더 길이 *4
	u_char Version : 4;//IP v4
	u_short TotalLength;//헤더 길이 + 데이터 길이/
	u_char Protocol;//프로토콜 종류(1. ICMP 2. IGMP 6. TP 17:UDP;
	ipaddress SenderAddress;
	ipaddress DestinationAddress;
	
}IPHeader;

void main()
{
	pcap_if_t *allDevice; //찾아낸 디바이스를 LinkedList로 묶고, 그 중 첫 번째 오브젝트를 담을 변수 생성
	pcap_if_t *device; //Linked List의 다음 오브젝트를 담을 공간
	char error[256]; //에러 메시지를 담을 변수 생성
	char counter = 0;

	pcap_t *pickedDev; //사용할 디바이스를 저장하는 변수

					//1. 장치 검색 (찾아낸 디바이스를 LinkedList로 묶음)
	if ((pcap_findalldevs(&allDevice, error)) == -1)//변수 생성시에는 1 포인터지만, pcap_findallDevice에 쓰는건 더블 포인트이므로 주소로 주어야 함.
													//pcap_if_t는 int형태를 반환하며, -1이 나올 경우, 디바이스를 찾지 못했을 경우이다.
		printf("장치 검색 오류");

	//2. 장치 출력
	int count = 0;
	for (device = allDevice; device != NULL; device = device->next)
		//dev에 allDevice의 첫 시작 주소를 넣으며, dev의 값이 NULL(끝)일 경우 종료, dev는 매 for마다 다음 주소값으로 전환
	{
		printf("┌%d 번 네트워크 카드───────────────────────────\n", count);
		printf("│어댑터 정보 : %s\n", device->name);
		printf("│어댑터 설명 : %s\n", device->description);
		printf("└────────────────────────────────────\n");
		count = count + 1;
	}
	//3. 네트워크 카드를 선택하고 선택된 디바이스로 수집할 패킷 결정하기
	printf("패킷을 수집할 네트워크 카드를 선택 하세요 : ");
	device = allDevice;//카드를 선택하지 않고 그냥 첫 번째 카드로 설정했음.

	int choice;
	scanf_s("%d", &choice);
	for (count = 0; count < choice; count++)
	{
		device = device->next;
	}

	//네트워크 장치를 열고, 수집할 패킷 양을 설정한다.
	pickedDev = pcap_open_live(device->name, 65536, 0, 1000, error);
	//랜카드의 이름, 수집할 패킷 크기(최대 65536), 프로미스큐어스모드(패킷 수집 모드) 설정, 패킷 대기 시간, 에러 정보를 저장할 공간)

	//4. 랜카드 리스트 정보를 저장한 메모리를 비워준다.
	pcap_freealldevs(allDevice);

	//5. 설정한 네트워크 카드에서 패킷을 무한 캡쳐 할 함수를 만들고 캡쳐를 시작한다.
	pcap_loop(pickedDev, 0, packet_handler, NULL);
}

//아래에서 사용할 수 있도록패킷 핸들러를 만든다.
void packet_handler(u_char *param, const struct pcap_pkthdr *h, const u_char *data)
//인자 = 파라미터, 패킷 헤더, 패킷 데이터(수신자 MAC 주소 부분 부터)
{
#define IPHEADER 0x0800
#define ARPHEADER 0x0806
#define RARPHEADER 0x0835
	//소스 읽을 때 가독성을 위해 상수를 문자로 바꾼다.

	Ethernet_Header *EH = (Ethernet_Header *)data;//data 주소에 저장된 14byte 데이터가 구조체 Ethernet_Header 형태로 EH에 저장된다.

	short int type = ntohs(EH->ptype);
	//EH->ptype은 빅 엔디언 형식을 취하므로,
	//이를 리틀 엔디언 형식으로 변환(ntohs 함수)하여 type에 저장한다.

	IPHeader *IH = (struct IPHeader*)(data + 14); //제일 처음 14byte는 이더넷 헤더(Layer 2) 그 위에는 IP헤더(20byte), 그 위에는 TCP 헤더...

	if(IH->Version != 4)
			return ;
	//ip버젼이 4가 아닌경우는 출력하지 않음

	printf("패킷 분석\n");
	//패킷 출력

	printf("┌─────────────────────────\n");
	printf("├Src MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->src[0], EH->src[1], EH->src[2], EH->src[3], EH->src[4], EH->src[5]);//송신자 MAC
	printf("├Dst MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->des[0], EH->des[1], EH->des[2], EH->des[3], EH->des[4], EH->des[5]);//수신자 MAC

	
		
		printf("버전 : %d\n", IH->Version);

		printf("헤더 길이 : %d\n", (IH->HeaderLength) * 4);

		printf("전체 크기 : %d\n", ntohs(IH->HeaderLength));//2 bytes 이상 부터는 무조건 뒤집어야 하므로 ntohs함수를 써서 뒤집는다.

		printf("출발 IP 주소 : %d.%d.%d.%d\n", IH->SenderAddress.ip1, IH->SenderAddress.ip2, IH->SenderAddress.ip3, IH->SenderAddress.ip4);
		printf("도착 IP 주소 : %d.%d.%d.%d\n", IH->DestinationAddress.ip1, IH->DestinationAddress.ip2, IH->DestinationAddress.ip3, IH->DestinationAddress.ip4);
		printf("├Protocol : IP\n");
	

	printf("└─────────────────────────\n");

}

