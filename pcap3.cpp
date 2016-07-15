#include"stdafx.h"
#include"pcap.h"
#include<WinSock2.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *h, const u_char *data);
//��Ŷ�� ���� ���� ���¿��� �а� ó���ϴ� �Լ�

typedef struct Ethernet_Header//�̴��� ��� ����ü
{
	u_char des[6];//������ MAC �ּ�
	u_char src[6];//�۽��� MAC �ּ�
	short int ptype;//�ڿ� ���� ��Ŷ�� �������� ����(��:ARP/IP/RARP)
			//IP ����� ���� ��� : 0x0800
			//ARP ����� ���� ��� : 0x0806
			//RARP ����� ���� ��� : 0x0835
}Ethernet_Header;


typedef struct ipaddress
{
	u_char ip1;
	u_char ip2;
	u_char ip3;
	u_char ip4;
}ip;

//IP ���������� ����� ������ ����ü ����
typedef struct IPHeader
{
	u_char HeaderLength : 4;//��� ���� *4
	u_char Version : 4;//IP v4
	u_short TotalLength;//��� ���� + ������ ����/
	u_char Protocol;//�������� ����(1. ICMP 2. IGMP 6. TP 17:UDP;
	ipaddress SenderAddress;
	ipaddress DestinationAddress;
	
}IPHeader;

void main()
{
	pcap_if_t *allDevice; //ã�Ƴ� ����̽��� LinkedList�� ����, �� �� ù ��° ������Ʈ�� ���� ���� ����
	pcap_if_t *device; //Linked List�� ���� ������Ʈ�� ���� ����
	char error[256]; //���� �޽����� ���� ���� ����
	char counter = 0;

	pcap_t *pickedDev; //����� ����̽��� �����ϴ� ����

					//1. ��ġ �˻� (ã�Ƴ� ����̽��� LinkedList�� ����)
	if ((pcap_findalldevs(&allDevice, error)) == -1)//���� �����ÿ��� 1 ����������, pcap_findallDevice�� ���°� ���� ����Ʈ�̹Ƿ� �ּҷ� �־�� ��.
													//pcap_if_t�� int���¸� ��ȯ�ϸ�, -1�� ���� ���, ����̽��� ã�� ������ ����̴�.
		printf("��ġ �˻� ����");

	//2. ��ġ ���
	int count = 0;
	for (device = allDevice; device != NULL; device = device->next)
		//dev�� allDevice�� ù ���� �ּҸ� ������, dev�� ���� NULL(��)�� ��� ����, dev�� �� for���� ���� �ּҰ����� ��ȯ
	{
		printf("��%d �� ��Ʈ��ũ ī�妡����������������������������������������������������\n", count);
		printf("������� ���� : %s\n", device->name);
		printf("������� ���� : %s\n", device->description);
		printf("��������������������������������������������������������������������������\n");
		count = count + 1;
	}
	//3. ��Ʈ��ũ ī�带 �����ϰ� ���õ� ����̽��� ������ ��Ŷ �����ϱ�
	printf("��Ŷ�� ������ ��Ʈ��ũ ī�带 ���� �ϼ��� : ");
	device = allDevice;//ī�带 �������� �ʰ� �׳� ù ��° ī��� ��������.

	int choice;
	scanf_s("%d", &choice);
	for (count = 0; count < choice; count++)
	{
		device = device->next;
	}

	//��Ʈ��ũ ��ġ�� ����, ������ ��Ŷ ���� �����Ѵ�.
	pickedDev = pcap_open_live(device->name, 65536, 0, 1000, error);
	//��ī���� �̸�, ������ ��Ŷ ũ��(�ִ� 65536), ���ι̽�ť����(��Ŷ ���� ���) ����, ��Ŷ ��� �ð�, ���� ������ ������ ����)

	//4. ��ī�� ����Ʈ ������ ������ �޸𸮸� ����ش�.
	pcap_freealldevs(allDevice);

	//5. ������ ��Ʈ��ũ ī�忡�� ��Ŷ�� ���� ĸ�� �� �Լ��� ����� ĸ�ĸ� �����Ѵ�.
	pcap_loop(pickedDev, 0, packet_handler, NULL);
}

//�Ʒ����� ����� �� �ֵ�����Ŷ �ڵ鷯�� �����.
void packet_handler(u_char *param, const struct pcap_pkthdr *h, const u_char *data)
//���� = �Ķ����, ��Ŷ ���, ��Ŷ ������(������ MAC �ּ� �κ� ����)
{
#define IPHEADER 0x0800
#define ARPHEADER 0x0806
#define RARPHEADER 0x0835
	//�ҽ� ���� �� �������� ���� ����� ���ڷ� �ٲ۴�.

	Ethernet_Header *EH = (Ethernet_Header *)data;//data �ּҿ� ����� 14byte �����Ͱ� ����ü Ethernet_Header ���·� EH�� ����ȴ�.

	short int type = ntohs(EH->ptype);
	//EH->ptype�� �� ����� ������ ���ϹǷ�,
	//�̸� ��Ʋ ����� �������� ��ȯ(ntohs �Լ�)�Ͽ� type�� �����Ѵ�.

	IPHeader *IH = (struct IPHeader*)(data + 14); //���� ó�� 14byte�� �̴��� ���(Layer 2) �� ������ IP���(20byte), �� ������ TCP ���...

	if(IH->Version != 4)
			return ;
	//ip������ 4�� �ƴѰ��� ������� ����

	printf("��Ŷ �м�\n");
	//��Ŷ ���

	printf("����������������������������������������������������\n");
	printf("��Src MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->src[0], EH->src[1], EH->src[2], EH->src[3], EH->src[4], EH->src[5]);//�۽��� MAC
	printf("��Dst MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->des[0], EH->des[1], EH->des[2], EH->des[3], EH->des[4], EH->des[5]);//������ MAC

	
		
		printf("���� : %d\n", IH->Version);

		printf("��� ���� : %d\n", (IH->HeaderLength) * 4);

		printf("��ü ũ�� : %d\n", ntohs(IH->HeaderLength));//2 bytes �̻� ���ʹ� ������ ������� �ϹǷ� ntohs�Լ��� �Ἥ �����´�.

		printf("��� IP �ּ� : %d.%d.%d.%d\n", IH->SenderAddress.ip1, IH->SenderAddress.ip2, IH->SenderAddress.ip3, IH->SenderAddress.ip4);
		printf("���� IP �ּ� : %d.%d.%d.%d\n", IH->DestinationAddress.ip1, IH->DestinationAddress.ip2, IH->DestinationAddress.ip3, IH->DestinationAddress.ip4);
		printf("��Protocol : IP\n");
	

	printf("����������������������������������������������������\n");

}

