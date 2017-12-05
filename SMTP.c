#include "nids.h"
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

void smtp_protocol_callback(struct tcp_stream *smtp_connection/*,void **arg*/)
{
    int i;
    char address_string[1024];
    char content[65535];
    //char content_urgent[65535];
    struct tuple4 ip_and_port=smtp_connection->addr;
    strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
    sprintf(address_string+strlen(address_string),":%i",ip_and_port.source);
    strcat(address_string,"<-------->");
    strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
    sprintf(address_string + strlen(address_string),":%i",ip_and_port.dest);
    strcat(address_string,"\n");
    switch (smtp_connection->nids_state) {
    case NIDS_JUST_EST:
        if(smtp_connection->addr.dest== 465)
        {
            /*smtp客户端和SMTP服务器端建立连接*/


            smtp_connection->client.collect++;
            /*SMTP客户端接收数据*/
            smtp_connection->server.collect++;
            /*SMTP服务器接收数据*/
            smtp_connection->server.collect_urg++;
            /*SMTP服务器接收紧急数据*/
            smtp_connection->client.collect_urg++;
            /*SMTP客户端接收紧急数据*/
            printf("%sSMTP发送方与SMTP接收方建立连接\n",address_string);
        }
        return;
    case NIDS_CLOSE:
        /*SMTP客户端与SMTP服务器连接正常关闭*/
        printf("--------------------------\n");
        printf("%sSMTP发送方与SMTP接收方连接正常关闭\n",address_string);
        return;

    case NIDS_RESET:
        /*SMTP客户端与SMTP服务器连接被reset关闭*/
        printf("------------------------\n");
        printf("%sSMTTP 发送方与SMTP接收方连接被RESET",address_string);
        return ;

    case NIDS_DATA:
        {
            /*SMTP协议接收到新的数据*/
            char status_code[4];
            struct half_stream *hlf;
            if(smtp_connection->server.count_new_urg)
            {
                printf("---------------------\n");
                stpcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                sprintf(address_string+strlen(address_string),":%i",ip_and_port.source);
                strcat(address_string,"urgent----->");
                strcat(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                sprintf(address_string+strlen(address_string),":%i",ip_and_port.dest);
                strcat(address_string,"\n");
                address_string[strlen(address_string)+1]=0;
                address_string[strlen(address_string)] = smtp_connection->server.urgdata;
                printf("%s",address_string);
                return ;
            }
            if(smtp_connection->client.count_new_urg)
            {
                printf("----------------\n");
                strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                sprintf(address_string+strlen(address_string),":%i",ip_and_port.source);
                strcat(address_string,"<----urgent");
                strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                sprintf(address_string+strlen(address_string),":%i",ip_and_port.dest);
                strcat(address_string,"\n");
                address_string[strlen(address_string)+1]=0;
                address_string[strlen(address_string)]=smtp_connection->client.urgdata;
                printf("%s",address_string);
                return;
            }
            if(smtp_connection->client.count_new)
            {
                hlf=&smtp_connection->client;
                strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.saddr))));
                sprintf(address_string+strlen(address_string),":%i",ip_and_port.source);
                strcat(address_string,"<-----");
                strcpy(address_string,inet_ntoa(*((struct in_addr*)&(ip_and_port.daddr))));
                sprintf(address_string+strlen(address_string),":%i",ip_and_port.dest);
                strcat(address_string,"\n");
                printf("-----------------------------------------\n");
                printf("%s",address_string);
                memcpy(content,hlf->data,hlf->count_new);
                content[hlf->count_new]='\0';
                if (strstr(strncpy(status_code, content, 3), "221"))
                    printf("connect stop\n");
                if (strstr(strncpy(status_code, content, 3), "250"))
                    printf("操作成功\n");
                content[hlf->count_new] = '\0';
                if (strstr(strncpy(status_code, content, 3), "220"))
                    printf("express server is ok\n");
                if (strstr(strncpy(status_code, content, 3), "354"))
                    printf("开始邮件输入，以\".\"结束\n");
                if (strstr(strncpy(status_code, content, 3), "334"))
                    printf("server reply checking\n");
                if (strstr(strncpy(status_code, content, 3), "235"))
                    printf("认证成功可以发送邮件了\n");
                for(i=0;i<hlf->count_new;i++)
                {
                    printf("%s",char_to_ascii(content[i]));
                }
                printf("\n");
            }
            else
            {

                /* SMTP服务器接收到新的数据 */
                hlf = &smtp_connection->server;
                strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                strcat(address_string, " ---> ");
                strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
                sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
                strcat(address_string, "\n");
                printf("--------------------------------\n");
                printf("%s", address_string);
                memcpy(content, hlf->data, hlf->count_new);
                content[hlf->count_new] = '\0';

                if (strstr(content, "EHLO"))
                    printf("EHLO命令\n");
                if (strstr(content, "QUIT"))
                    printf("用户密码为\n");
                if (strstr(content, "DATA"))
                    printf("开始传输数据\n");
                if (strstr(content, "MAIL FROM"))
                    printf("发送方邮件地址为\n");
                if (strstr(content, "RCPT TO"))
                    printf("接收方邮件地址为\n");
                if (strstr(content, "AUTH"))
                    printf("请求认证\n");
                if (strstr(content, "LOGIN"))
                    printf("认证机制为LOGIN\n");
                for (i = 0; i < hlf->count_new; i++)
                {
                    printf("%s", char_to_ascii(content[i]));
                }
                printf("\n");
                if(strstr(content,"\n."))
                    printf("数据传输结束");
            }
        }
    default:
        break;
    }
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
    nids_register_tcp(smtp_protocol_callback);
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

