#include "head.h"
int sockfd;
int quit = 0;
void *pthread_recv(void *arg)
{
    msg_t msg; // 接收消息的结构体，我会放到head.h文件中解释
    bzero(&msg, 0); // 初始化
    while (1) //循环
    {
    	/* 阻塞接收函数,ret返回值用处来表明接收消息是否正常 */
    	/* 同时也能知道其他客户端是否还在不在聊天室,比如下文的等于0 */
        int ret = recv(sockfd, &msg, sizeof(msg), 0); 
        if (ret > 0)
        {
        	/* type变量是一个区分,1为正常消息,0为不正常,通常是有客户端主动正常退出 */
            if (msg.type == 1 && strlen(msg.message) > 0)
            {
            	/* 打印消息同时打印是哪个客户端打印的 */
                printf("客户端(%s:%d):%s\n", inet_ntoa(msg.cli.client.sin_addr), ntohs(msg.cli.client.sin_port), msg.message);
            }
            else
            {
                printf("%s\n", msg.message);
            }
        }
        /* 为0就是某某客户端断开连接 */
        else if (ret == 0)
        {
            printf("%s\n", msg.message);
        }
    }
}

void *pthread_send(void *arg)
{
    msg_t msg;
    bzero(&msg, 0);
    while (1)
    {
    	/* 读取输入 */
        scanf("%s", msg.message);
        /* 防止读取到一个回车就发送 */
        if (getchar() == '\n' && msg.message[0] != '\n')
        {
        	/* 安全起先还是加了一个\0 */
            int len = strlen(msg.message);
            msg.message[len + 1] = '\0';
            send(sockfd, &msg, sizeof(msg), 0);
            /* 如果是quit的话令quit变量为true,这样主程序会结束 */
            if (!strcmp(msg.message, "quit"))
            {
                quit = 1;
                break;
            }
            memset(msg.message, 0, sizeof(msg.message));
        }
    }
}

int main()
{
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverSock;
    socklen_t serverLen = sizeof(struct sockaddr_in);
    serverSock.sin_addr.s_addr = htonl(INADDR_ANY);
    serverSock.sin_port = htons(PORT);
    serverSock.sin_family = AF_INET;

    connect(sockfd, (struct sockaddr *)&serverSock, serverLen);
    printf("=====欢迎加入聊天室=====\n");
    printf("  退出服务器请输入quit  \n");
    msg_t msg;
    bzero(&msg, 0);
    pthread_t pthreadSend;
    pthread_create(&pthreadSend, NULL, pthread_send, NULL);
    pthread_t pthreadRecv;
    pthread_create(&pthreadRecv, NULL, pthread_recv, NULL);
    while (!quit)
        ;
    return 0;
}
