/*serve_tcp.c*/
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<string.h>

int main(){
	//创建套接字
	int serv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	//初始化socket元素
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_port = htons(1234);

	//绑定文件描述符和服务器的ip和端口号
	bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

	//进入监听状态，等待用户发起请求
	listen(serv_sock, 20);
	//接受客户端请求
	//定义客户端的套接字，这里返回一个新的套接字，后面通信时，就用这个clnt_sock进行通信
	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size = sizeof(clnt_addr);
	int clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

	//接收客户端数据，并响应
	char str[256];
	read(clnt_sock, str, sizeof(str));
	printf("client send: %s\n",str);
	strcat(str, "+ACK");
	write(clnt_sock, str, sizeof(str));

	//关闭套接字
	close(clnt_sock);
	close(serv_sock);

	return 0;
}

