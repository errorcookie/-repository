#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <time.h>


struct ether_header
{
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
    u_int16_t ether_type;
};

typedef u_int32_t in_addr_t;

/*struct in_addr
{
    in_addr_t s_addr ;
};*/
/*ARP 是根据IP地址获取物理地址的TCP/IP协议*/
struct arp_header
{
    u_int16_t arp_hardware_type;
    /*硬件地址类型 2个字节 表明ARP 实现在何种类型的网络上 值为1：表示以太网*/
    u_int16_t arp_protocol_type;
    /*协议类型：占2个字节表示要映射的协议地址类型 IP0800*/
    u_int8_t arp_hardware_length;
    /*硬件地址长度：占1个字节 表示MAC地址长度，其值为6个字节*/
    u_int8_t arp_protocol_length;
    /*协议地址长度： 占1个字节 表示IP地址长度，此处值4个字节*/
    u_int16_t arp_operation_code;
    /*操作类型：占2个字节，表示ARP数据包类型.值为1：ARP请求.值为2：ARP应答*/
    u_int8_t arp_source_ethernet_address[6];
    /*源MAC地址：占6个字节，表示发送端IP地址*/
    u_int8_t arp_source_ip_address[4];
    /*源IP地址： 占4个字节，表示发送端IP地址*/
    u_int8_t arp_destination_ethernet_address[6];
    /*目的以太网地址：占6个字节，表示目标设备的MAC物理地址  （该MAC为网关MAC地址）*/
    u_int8_t arp_destination_ip_address[4];
    /*目的IP地址：占4个字节，表示目标设备的IP地址  （为已知目标主机IP）*/

};
void arp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
    struct arp_header *arp_protocol;
    u_short protocol_type;
    u_short hardware_type;
    u_short operation_code;
    u_char *mac_string;
    struct in_addr source_ip_address;
    struct in_addr destination_ip_address;
    u_char hardware_length;
    u_char protocol_length;
    printf("-------------- ARP Protocol(Network Layer)---------------\n");
    arp_protocol = (struct arp_header*)(packet_content+14);
    hardware_type=ntohs(arp_protocol->arp_hardware_type);
    protocol_type=ntohs(arp_protocol->arp_protocol_type);
    operation_code=ntohs(arp_protocol->arp_operation_code);
    /*ntohs()是一个函数名，作用是将一个16位数由网络字节顺序转换为主机字节顺序*/
    hardware_length=arp_protocol->arp_hardware_length;
    protocol_length=arp_protocol->arp_protocol_length;
    printf("ARP Hardware Type:%d\n",hardware_type);
    printf("ARP Protocol Type:%d\n",protocol_type);
    printf("ARP Hardware Length:%d\n",hardware_type);
    printf("ARP Protocol Length:%d\n",protocol_length);
    printf("ARP Operation:%d\n",operation_code);
    switch(operation_code)
    {
        case 1:
        printf("ARP Request Protocol\n");
        break;
        case 2:
        printf("ARP Reply Protocol\n");
        break;
        case 3:
        printf("RARP Request Protocol\n");
        break;
        case 4:
        printf("RARP Reply Protocol\n");
        break;
        default:
        break;
    }
    printf("Ethernet Source Address is :\n");
    mac_string=arp_protocol->arp_source_ethernet_address;
    printf("%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    memcpy((void*)&source_ip_address,(void*)arp_protocol->arp_source_ip_address,sizeof(struct in_addr));
    printf("Source IP Address;%s\n",inet_ntoa(source_ip_address));
    /*将一个十进制网络字节序转换为点分十进制IP格式的字符串*/
    printf("Ethernet Destination Address is:\n");
    mac_string=arp_protocol->arp_destination_ethernet_address;
    printf("%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    memcpy((void*)&destination_ip_address,(void*)&arp_protocol->arp_destination_ip_address,sizeof(struct in_addr));
    printf("Destination IP Address:%s\n",inet_ntoa(destination_ip_address));
    /*memcpy函数的功能是从源src所指的内存地址的起始位置开始拷贝n个字节到目标dest所指的内存地址的起始位置中。void *memcpy(void *dest, const void *src, size_t n);*/
}
void ethernet_protocol_packet_callback(u_char *argument,const struct pacp_pkthdr *packet_header,const u_char *packet_content)
{
    u_short ether_type;
    struct ether_header *ethernet_protocol;
    u_char *mac_string;
    static int packet_number=1;
    printf("**********************************\n");
    printf("The %d ARP packet is capture is capture.\n",packet_number);
    printf("------ Ethernet Protocol (Link Layer) ------\n ");
    ethernet_protocol=(struct ethernet*)packet_content;
    printf("Ethernet type is:\n");
    ether_type=ntohs(ethernet_protocol->ether_type);
    printf("%04x\n",ether_type);
    switch(ether_type)
    {
        case 0x0800:
        printf("The network layer is IP protocol");
        break;
        case 0x0806:
        printf("The network layer is ARP protocol\n");
        break;
        case 0x8035:
        printf("The network layer is RARP protocol");
        break;
        default:
        break;
    }
    printf("Mac Source Address is:\n");
    mac_string=ethernet_protocol->ether_shost;
    printf("%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    /*将一个十进制网络字节序转换为点分十进制IP格式的字符串*/
    printf("Ethernet Destination Address is:\n");
    mac_string=ethernet_protocol->ether_dhost;
    printf("%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));

}
int main()
{
        //Libpcap句柄
        pcap_t *pcap_handle;
        //错误信息
        char error_content[PCAP_ERRBUF_SIZE];
        //网络接口
        char *net_interface;
        //过滤规则
        struct bpf_program bpf_filter;
        //过滤规则字符串，此时表示本程序只是捕获IP协议的数据包，同样也是以太网数据包
        char bpf_filter_string[] = "ip";
        //网络掩码
        bpf_u_int32 net_mask;
        //网络地址
        bpf_u_int32 net_ip;
        //获得网络接口
        net_interface = pcap_lookupdev(error_content);
        //获得网络地址和网络掩码
        //参数列表：网络接口、网络地址、网络掩码、错误信息
        pcap_lookupnet(net_interface , &net_ip , &net_mask , error_content);
        //打开网络接口
        //参数列表：网络接口、数据包大小、混杂模式、等待时间、错误信息
        pcap_handle = pcap_open_live(net_interface , BUFSIZ , 1 , 0 , error_content);
        //编译过滤规则
        //参数列表：Libpcap句柄、BPF过滤规则、过滤规则字符串、优化参数、网络地址
        pcap_compile(pcap_handle , &bpf_filter , bpf_filter_string , 0 , net_ip);
        //设置过滤规则
        //参数列表：Libpcap句柄、BPF过滤规则
        pcap_setfilter(pcap_handle , &bpf_filter);
        if(pcap_datalink(pcap_handle) != DLT_EN10MB)
                return 0;
        //无限循环捕获网络数据包，注册回到函数 ethernet_protocol_packet_callback(),捕获每个数据包都要调用此回调函数进行操作
        //参数列表：Libpcap句柄、捕获数据包的个数（此处-1表示无限循环）、回调函数、传递给回调函数的参数
        pcap_loop(pcap_handle , -1 , ethernet_protocol_packet_callback , NULL);
        //关闭Libpcap操作
        pcap_close(pcap_handle);
        return 0;
}
