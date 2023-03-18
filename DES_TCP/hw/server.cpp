#include<stdio.h>
#include<iostream>
#include<sys/socket.h>
#include<netinet/in.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<string.h>
#include <pthread.h>
#include"newdes.cpp"

int serv_sock;
bool quit=false;

class Node{
public:
    struct sockaddr_in client;
    int fd;
};

//创建套接字
int CreateSock(){
    int serverSock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    return serverSock;
}

//初始化socket元素
sockaddr_in CreateSockAddrIn(std::string ip,int port){
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(ip.c_str());
	serv_addr.sin_port = htons(port);
    return serv_addr;
}


void *pthread_send(void* arg){
    std::cout<<"成功创建发送线程"<<std::endl;
    char buffer[7500];
    Node*node = (Node*)arg;
    while(true){
        std::cin.getline(buffer,900);
        //getchar();
        std::string s = buffer;
        std::string fin = "quit";
        if(s.find(fin)!=std::string::npos){
            quit=true;
            break;
        }
        if(s.size()>900){
            std::cout<<"输入过长，请重新输入"<<std::endl;
            continue;
        }
        //现在s和buffer中存储了同样的内容，要把这个内容传送给加密函数加密。
        s = EnryptForTCP(s);//对输入的内容进行DES加密
        memset(buffer,0,7500);
        memcpy(buffer,s.c_str(),s.size());
        int ret = send(node->fd,buffer,7500,0);
        if(ret==-1){
            std::cout<<"发送失败"<<std::endl;
            std::cout<<errno<<std::endl;
        }else{
            std::cout<<"发送成功"<<std::endl;
        }
        memset(buffer,0,7500);
    }
    return nullptr;
}

void *pthread_recv(void* arg){
    std::cout<<"成功创建接收线程"<<std::endl;
    char buffer[7500];
    int sockfd = ((Node*)arg)->fd;
    while(true){
        int ret = recv(sockfd,buffer,7500,0);
        if(ret>0){
            std::string s = buffer;
            std::cout<<s<<std::endl;
            s = DecryptForTCP(s);
            std::cout<<s<<std::endl;
        }
        memset(buffer,0,7500);
        if(quit){
            break;
        }
    }
    return nullptr;
}

void *pthread_accept(void *arg){
    std::cout<<"成功创建监听线程"<<std::endl;
    struct sockaddr_in clientSock;
    socklen_t clientLen = sizeof(clientSock);
    //accpet
    int acceptedFd = accept(serv_sock, (sockaddr *)&clientSock, &clientLen);
    std::cout<<"成功连接客户端"<<std::endl;
    Node* node=new Node();
    node->client = clientSock;
    node->fd = acceptedFd;
    pthread_t pthreadSend;
    pthread_t pthreadRecv;
    pthread_create(&pthreadSend,NULL,pthread_send,(void *)node);
    pthread_create(&pthreadRecv,NULL,pthread_recv,(void *)node); 
    
    while(true){
        if(quit){
            close(acceptedFd);
            break;
        }
    }
    return nullptr;
}

int main(){
    serv_sock = CreateSock();
    struct sockaddr_in serv_addr = CreateSockAddrIn("127.0.0.1",6803);
    std::cout<<"ip、端口绑定完成"<<std::endl;
    //绑定文件描述符和服务器的ip和端口号
    bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    //进入监听状态，等待用户发起请求
	listen(serv_sock, 5);
    //创建专门accept的线程
    pthread_t acceptPthread;
    pthread_create(&acceptPthread,NULL,pthread_accept,NULL);
    while(true){
        if(quit){
            close(serv_sock);
            break;
        }
    }
    std::cout<<"成功退出"<<std::endl;
    return 0;

}