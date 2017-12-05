#include <nids.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
char ascii_string[10000];
char *char_to_ascii(char ch)
{
    char *string;
    ascii_string[0]=0;
    string=ascii_string;
    if(isgraph(ch))
    *string++=ch;
    else if(ch==' ')
    *string++=ch;
    else if(ch=='\n'||ch=='\r')
    *string++=ch;
    else
    *string++='.';
    *string=0;
    return ascii_string;
}
//下面是分析telnet协议的回调函数
void telnet_protocol_callback(struct tcp_stream *telnet_connection/*,void **arg*/)
{
    int i;
    char address_string[1024];
    char content[65535];
    //char content_urgent[65535];
    struct tuple4 ip_and_port=telnet_connection->addr;
    strcpy(address_string,inet_ntoa(*((struct  in_addr*)&(ip_and_port.saddr))));
    sprintf(address_string+strlen(address_string), ":%i",ip_and_port.source);
    strcat(address_string,"<---->");
    strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
    sprintf(address_string+strlen(address_string),":%i",ip_and_port.dest);
    strcat(address_string,"\n");
    switch(telnet_connection->nids_state)
    {
     case NIDS_JUST_EST:
          if(telnet_connection->addr.dest==23)
            {
                /*Telnet客户端和Telnet服务器端建立连接*/
                telnet_connection->client.collect++;
                /*Telnet客户端接收数据*/
                telnet_connection->server.collect++;
                /*Telnet服务器端接收数据*/
                telnet_connection->client.collect_urg++;
                /*Telnet客户端接收紧急数据*/
                telnet_connection->server.collect_urg++;
                /*Telnet服务器端接收紧急数据*/
                printf("%sTelnet客户端与Telnet服务器建立连接\n",address_string);
            }
            return ;
    case NIDS_CLOSE:
        /*Telnet协议连接正常关闭*/
        printf("------------------------------------\n");
        printf("%sTelnet客户端与Telnet服务器端连接正常关闭\n",address_string);
        return ;
        case NIDS_RESET:
        /*Telnet协议连接被RST关闭*/
        printf("-----------------------------------\n");
        printf("%sTelnet客户端与Telnet服务器端连接被REST关闭\n",address_string);
        return ;
    case NIDS_DATA:
        {
            /*Telnet协议有新的数据到达*/
            struct half_stream *hlf;
            if(telnet_connection->server.count_new_urg)
            {
                /*Telnet服务器接收到新的紧急数据*/
                printf("----------------------------------\n");
                strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                sprintf(address_string+strlen(address_string),":%i",ip_and_port.source);
                strcat(address_string,"urgent---->");
                strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                sprintf(address_string+strlen(address_string),":%i",ip_and_port.dest);
                strcat(address_string,"\n");
                address_string[strlen(address_string)+1]=0;
                address_string[strlen(address_string)]=telnet_connection->server.urgdata;
                printf("%s",address_string);
                return ;
        }
        if(telnet_connection->client.count_new_urg)
        {
            /*Telnet客户端接收到新的紧急数据*/
            printf("-------------------------------\n");
            strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
            sprintf(address_string+strlen(address_string),": %i",ip_and_port.source);
            strcat(address_string,"<----urgent");
            strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
            sprintf(address_string+strlen(address_string),": %i",ip_and_port.dest);
            strcat(address_string,"\n");
            address_string[strlen(address_string)+1]=0;
            address_string[strlen(address_string)]=telnet_connection->client.urgdata;
            printf("%s",address_string);
            return ;
        }
            if(telnet_connection->client.count_new)
            {
                /*Telnet客户端接收到新的数据*/
                hlf=&telnet_connection->client;
                strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                sprintf(address_string+strlen(address_string),": %i",ip_and_port.source);
                strcat(address_string,"<----");
                strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                sprintf(address_string + strlen(address_string), ": %i",
                ip_and_port.dest);
                strcat(address_string,"\n");
                printf("---------------------------\n");
                printf("%s",address_string);
                //输出telnet客户端收到的新的数据
                memcpy(content,hlf->data,hlf->count_new);
                content[hlf->count_new]='\0';
                for(i=0;i<hlf->count_new;i++)
                {
                printf("%s",char_to_ascii(content[i]));
                }
                printf("\n");
            }
            else
            {
                //telnet服务器接收到新的数据
                hlf=&telnet_connection->server;
                strcpy(address_string,   inet_ntoa(*((struct   in_addr*)
                &(ip_and_port.saddr))));
                sprintf(address_string + strlen(address_string), ":%i",ip_and_port.source);
                strcat(address_string,"--->");
                strcat(address_string, inet_ntoa(*((struct  in_addr*)
                &(ip_and_port.daddr))));
                sprintf(address_string + strlen(address_string),":%i",ip_and_port.dest);
                strcat(address_string,"\n");
                printf("------------------------------");
                printf("%s",address_string);
                //输出telnet服务器接收到的新的数据
                memcpy(content, hlf->data,hlf->count_new);
                content[hlf->count_new]='\0';
                for(i=0;i<hlf->count_new;i++)
                {
                    printf("%s",char_to_ascii(content[i]));
                }
                printf("\n");
            }
        }
        default:
        break;
    }
    return;
}

int main()
{
    //设置网络接口
   //  nids_params.device = "eth0";
       struct nids_chksum_ctl tmp;
    // printf("nids_chksum_ctl:%d\n",tmp.action);

    //关闭数据校验
         tmp.netaddr = 0;
         tmp.mask = 0;
         tmp.action = 1;
         nids_register_chksum_ctl(&tmp, 1);
  printf("nids_chksum_ctl:%d\n",tmp.action);
    if(!nids_init())
    {
        printf("%s\n",nids_errbuf);
        exit(1);
    }
    nids_register_tcp(telnet_protocol_callback);
    /*

    * 返回值 : 无

    * 参 数 : 回调函数

    * 功 能 : 注册一个 TCP 连接的回调函数 . 回调函数的类型定义如下 :

    void tcp_callback(struct tcp_stream * ns,void ** param)

    ns 表示一个 TCP 连接的所有信息 , param 表示要传递的参数信息 , 可以指向一个 TCP 连接的私有数据

    此回调函数接收的 TCP 数据存放在 half_stream 的缓存中 , 应该马上取出来 , 一旦此回调函数返回 ,此数据缓存中存储的数据就不存在

    了 .half_stream 成员 offset 描述了被丢弃的数据字节数 . 如果不想马上取出来 , 而是等到存储一定数量的数据之后再取出来 , 那么可

    以使用函数 nids_discard(struct tcp_stream * ns, int num_bytes) 来处理 . 这样回调函数返回时 ,Libnids 将丢弃缓存数据之前

    的 num_bytes 字节的数据 . 如果不调用 nids_discard() 函数 , 那么缓存数据的字节应该为 count_new 字节 . 一般情况下 , 缓存中的数据

    应该是 count-offset 字节

    */
    /**/
    nids_run();
    return 0;
}
