#include "head.h"
msg_t phead;
int sockfd;

void delNodeFromList(msg_t *phead, int fd)
{
    if (phead == NULL)
        return;
    cli_t *p = &phead->cli;
    cli_t *pDel = NULL;
    /* 遍历链表找到要删除客户端的节点令pDel指向它 */
    while (p->next != NULL)
    {
        if (p->next->fd == fd)
        {
            pDel = p->next;
            break;
        }
        p = p->next;
    }
    p->next = pDel->next;
    pDel->next = NULL;
    free(pDel);
    pDel = NULL;
}

void *pthread_common(void *arg)
{
	/*传递过来的pNode结构体中包含客户端的信息*/
    cli_t *pNode = (cli_t *)arg;
    /*打印给服务端显示*/
    printf("客户端(%s:%d)加入聊天室\n", inet_ntoa(pNode->client.sin_addr), ntohs(pNode->client.sin_port));
    /*如果客户端链表大于1就转发某某加入聊天室的信息,并通知其他客户端*/
    if (phead.size > 1)
    {
        cli_t *p = &phead.cli;
        msg_t msg;
        bzero(&msg, 0);
        msg.cli = *pNode;
        msg.type = 0;
        sprintf(msg.message, "客户端(%s:%d)加入聊天室", inet_ntoa(pNode->client.sin_addr), ntohs(pNode->client.sin_port));
        while (p->next != NULL)
        {
            p = p->next;
            /*除自己外不用发*/
            if (p->fd == pNode->fd)
                continue;
            send(p->fd, &msg, sizeof(msg), 0);
        }
    }
    /*死循环,接收和转发消息或者处理客户端消息*/
    while (1)
    {
        msg_t msgs;
        bzero(&msgs, 0);
        int ret = recv(pNode->fd, &msgs, sizeof(msgs), 0);
        /* 这里对客户端链表上锁,以防止两个或多个客户端同时退出造成 */
        /* 服务端崩溃或者转发消息失败 */
        pthread_mutex_lock(&phead.lock);
        if (ret > 0)
        {
        	/*先对发来quit消息的客户端进行处理*/
            if (!strcmp("quit", msgs.message))
            {
                phead.size--;
                msgs.type = 0;
                printf("客户端(%s:%d)退出聊天室\n", inet_ntoa(pNode->client.sin_addr), ntohs(pNode->client.sin_port));
                sprintf(msgs.message, "客户端(%s:%d)退出聊天室", inet_ntoa(pNode->client.sin_addr), ntohs(pNode->client.sin_port));
                cli_t *p = &phead.cli;
                while (p->next != NULL)
                {
                    p = p->next;
                    if (p->fd == pNode->fd)
                    {
                        continue;
                    }
                    send(p->fd, &msgs, sizeof(msgs), 0);
                }
                /* 待消息转发结束之后解锁链表 */
                pthread_mutex_unlock(&phead.lock);
                /* 从链表中删除此客户端信息 */
                delNodeFromList(&phead, pNode->fd);
                /* 关闭此套接字 */
                close(pNode->fd);
                /* 线程结束 */
                pthread_cancel(pthread_self());
                bzero(&msgs, 0);
                break;
            }
            else // 如果不是quit就正常转发此客户端发来的消息
            {
                msgs.cli = *pNode;
                cli_t *p = &phead.cli;
                /* type = 1就是为了能够客户端那边打印客户端消息 */
                msgs.type = 1; 
                while (p->next != NULL)
                {
                    p = p->next;
                    if (p->fd == pNode->fd)
                        continue;
                    send(p->fd, &msgs, sizeof(msgs), 0);
                }
                /* 正常发送消息结束后解锁链表 */
                pthread_mutex_unlock(&phead.lock);
            }
        }
        /* 这就是ret小于等于0的情况了,表示客户端意外退出 */
        /* 其处理方法和上边quit的处理相同,不过就是发送消息改为了 */
        /* 意外退出而已 */
        else
        {
            phead.size--;
            msgs.type = 0;
            printf("客户端(%s:%d)意外退出聊天室\n", inet_ntoa(pNode->client.sin_addr), ntohs(pNode->client.sin_port));
            sprintf(msgs.message, "客户端(%s:%d)意外退出聊天室", inet_ntoa(pNode->client.sin_addr), ntohs(pNode->client.sin_port));
            cli_t *p = &phead.cli;
            while (p->next != NULL)
            {
                p = p->next;
                if (p->fd == pNode->fd)
                {
                    continue;
                }
                send(p->fd, &msgs, sizeof(msgs), 0);
            }
            pthread_mutex_unlock(&phead.lock);
            delNodeFromList(&phead, pNode->fd);
            pthread_cancel(pthread_self());
            close(pNode->fd);
            bzero(&msgs, 0);
            break;
        }
    }
}

void *pthread_accept(void *arg)
{
    struct sockaddr_in clientSock;
    socklen_t clientLen = sizeof(struct sockaddr_in);
    printf("===========聊天室已创建===========\n");
    while (1)
    {
        int acceptFd = accept(sockfd, (struct sockaddr *)&clientSock, &clientLen);
        /*pNode保存客户端信息,并将这个结构体传递给common的线程*/
        /*common线程是把客户端加入到链表中之后再创建的用于接收和转发聊天*/
        cli_t *pNode = (cli_t *)malloc(sizeof(cli_t));
        pNode->client = clientSock;
        pNode->fd = acceptFd;
        pNode->next = NULL;
        /*采用头插法*/
        if (phead.size > 0)
        {
            cli_t *p = phead.cli.next;
            phead.cli.next = pNode;
            pNode->next = p;
        }
        else if (phead.size == 0)
        {
            phead.cli.next = pNode;
        }
        phead.size++;
        pthread_t commonPthread;
        /*创建聊天线程*/
        pthread_create(&commonPthread, NULL, pthread_common, (void *)pNode);
        pthread_detach(commonPthread);
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
    bind(sockfd, (struct sockaddr *)&serverSock, serverLen);

    listen(sockfd, 0);

    pthread_t acceptPthread;
    pthread_create(&acceptPthread, NULL, pthread_accept, NULL);
    while (1)
        ;
    return 0;
}
