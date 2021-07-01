# Linux 高性能服务器编程——笔记

## 第5章 Linux网络编程基础API

socket的主要API都定义在sys/socket.h头文件中。网络信息API都定义在netdb.h头文件中。

### 5.1 socket地址API

#### 5.1.1主机字节序和网络字节序

大端字节序，小端字节序。

```c
#include <stdio.h>
void byteorder()
{
    /*共同体的素有成员占用同一段内存，修改一个成员会影响其余成员*/
	union
	{
		short value;
		char union_bytes[ sizeof( short ) ];
	} test;
	test.value = 0x0102;
	if (  ( test.union_bytes[ 0 ] == 1 ) && ( test.union_bytes[ 1 ] == 2 ) )
	{
		printf( "big endian\n" );
	}
	else if ( ( test.union_bytes[ 0 ] == 2 ) && ( test.union_bytes[ 1 ] == 1 ) )
	{
		printf( "little endian\n" );
	}
	else
	{
		printf( "unknown...\n" );
	}
}

int main()
{
    byteorder();
    return 0;
}
```

发送段总要把发送的数据转化为`大端字节序`数据后再发送。

- 小端字节序：主机字节序；大端字节序：网络字节序。
- 同一台机器上的两个进程通信，也需要考虑字节序问题。（JAVA虚拟机采用大端字节序）。

```c
#include<netinet/in.h>
unsigned long int htonl(unsigned long int hostlong);
unsigned short int htons(unsigned short int hostshort);
unsigned long int ntohl(unsigned long int netlong);
unsigned short int ntohs(unsigned short int netshort);
/*长整型函数通常用来转换IP地址，短整型函数用来转换端口号*/
```

#### 5.1.2通用socket地址

```c
#include<bits/socket.h>
struct sockaddr
{
    sa_family_t sa_family;//地址族类型变量。地址组类型通常与协议族类型（domain）对应
    char sa_data[14];  //存放socket地址，不同协议族的地址值具有不同的含义和长度。
};

//为了有足够大的空间用于存放地址值
struct sockaddr_storage
{
    sa_family_t sa_family;
    unsigned long int __ss_align;  //保证内存对齐
    char __ss_padding[128-sizeof(__ss_align)];
};
```

|  协议族  |  地址族  |       描述       |                   地址值含义和长度                    |
| :------: | :------: | :--------------: | :---------------------------------------------------: |
| PF_UNIX  | AF_UNIX  | UNIX本地域协议族 |                   文件路径名108字节                   |
| PF_INET  | AF_INET4 |  TCP/IPv4协议族  |              16bit端口号，32bitIPv4地址               |
| PF_INET6 | AF_INET6 |  TCP/IPv6协议族  | 16bit端口号，32bit流标识，128bitIPv6地址，32bit范围ID |

#### 5.1.3专用socket地址

UNIX本地域协议族

```c
#include<sys/un.h>
struct sockaddr_un
{
    sa_family_t sin_family;  //AF地址族
    char sun_path[108];      //文件路径名
};
```

TCP/IP协议族

```c
//IPv4
struct sockaddr_in
{
    sa_family_t sin_family;
    u_int16_t sin_port;        //端口号，用网络字节序表示
    struct in_addr sin_addr;   //IPv4地址结构体
};
struct in_addr
{
    u_int32_t s_addr;
};

//IPv6
struct sockaddr_in6
{
    sa_family_t sin6_family;
    u_int16_t sin6_port;
    u_int32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    u_int32_t sin6_scope_id;   //scope ID,尚处于实验阶段。
};

struct in6_addr
{
    unsigned char sa_addr[16]; //16字节IP地址
};
```

`所有专用socket地址类型的变量在实际使用时都需要转化为通用socket地址类型sockaddr(强制转换即可)`。所有socket编程接口使用的地址参数的类型都是sockaddr。

#### 5.1.4 IP地址转换函数

（IPv4点分十进制和整数的转换）

```c
#include<arpa/inet.h>
/*将点分十进制转换为整数，失败时返回INADDR_NONE*/
in_addr_t inet_addr(const char* strptr);
/*和inet_addr有相同的功能，但是将转化结果存储在参数inp指向的地址结构中成功时返回1，失败返回0*/
int inet_aton(const char*cp, struct in_addr* inp);
/*整数转换为点分十进制字符串，内部用一个静态变量存储转化结果，函数的返回值指向该静态内存，inet_ntoa不可重入*/
char* inet_ntoa(struct in_addr in);
```

```c
//可以同时适用于IPv4和IPv6
#include<arpa/inet.h>
/*将用字符串表示的src转换成整数存在dst中。af为AF_INET或AF_INET6。成功时返回1，失败则返回0，并设置errno*/
int inet_pton(int af, const char* src, void* dst);
/*相反的转换。cnt指定目标存储单元的大小,使用宏INET_ADDRSTRLEN, INET6_ADDRSTRLEN。成功时返回目标存储单元的地址，失败则返回NULL并设置errno*/
const char* inet_ntop(int af, const void*src, char* dst, socklen_t cnt);
```

### 5.2创建socket

```c
#include<sys/types.h>
#include<sys/socket.h>
/*domain代表底层协议，type参数指定服务类型，主要有SOCK_STREAM(流服务)和SOCK_URGRAME(数据报服务)。2.6.17起,type参数可以接收上述服务类型与下面两个重要的标志相与的值：SOCK_NONBLOCK和SOCK_CLOEXEC。分别表示将新创建的socket设为非阻塞的，以及用fork调用创建子进程时在子进程中关闭该socket。protocol几乎在所有情况下设置为0。*/
int socket(int domain, int type, int protocol);
//调用成功时返回一个socket文件描述符，失败则返回-1并设置errno
```

### 5.3 命名socket

将一个socket与socket地址绑定称为给socket的命名。在`服务器`程序中，我们通常要命名socket，因为只有命名后客户端才能知道该如何连接它。客户端则通常不需要命名socket而是采用匿名方式，用OS自动分配的socket地址。

``` c
#include<sys/types.h>
#include<sys/socket.h>
/*bind将my_addr所指的socket地址分配给未命名的sockfd文件描述符，addrlen参数指出该socket地址的长度*/
int bind(int sockfd, const struct sockaddr* my_addr, socklen_t addrlen);
//成功时返回0，失败则返回-1并设置errno。
```

两种常见的errno

- EACCESS: 被绑定的地址是受保护地址，仅超级用户能够访问。
- EADDRINUSE: 被绑定的地址正在使用中。

### 5.4 监听socket

socket被命名号还需要创建一个监听队列才能接受客户连接。

```c
#include<sys/socket.h>
/*sockfd参数指定被监听的socket。backlog参数提示内核监听队列的最大长度。超过backlog,服务器不受理新的客户连接，客户端也将收到ECONNREFUSED错误信息。内核版本2.2之后，只表示完全连接状态的socket的上限，处于半连接状态的socket上限由/proc/sys/net/ipv4/tcp_max_syn_backlog内核参数定义。*/
int listen(int sockfd, int backlog);
//listen成功时返回0，失败返回-1设置errno
```

```c
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<signal.h>
#include<unistd.h>
#include<stdlib.h>
#include<assert.h>
#include<stdio.h>
#include<string.h>
#include<stdbool.h>  //bool报错
#include<libgen.h>   //basename报错

static bool stop=false;

static void handle_term(int sig)
{
	stop=true;
}

int main(int argc, char* argv[])
{
	signal(SIGTERM, handle_term);  //以handle_term方式处理SIGTERM

	if(argc<=3)
	{
		printf("usage: %s ip_address port_number backlag\n", basename(argv[0]));
		return 1;
	}
	const char* ip=argv[1];
	int port=atoi(argv[2]);
	int backlog=atoi(argv[3]);
	int sock=socket(PF_INET,SOCK_STREAM,0);  //创建socket
	assert(sock>=0);

	struct sockaddr_in address;    //建立ipv4专用地址
	bzero(&address,sizeof(address));  //初始化address空间
	address.sin_family=AF_INET;
	inet_pton(AF_INET,ip,&address.sin_addr);  //将ip中的字符串转换为整数，存放address中。函数同时带有字节序转换功能
	address.sin_port=htons(port);   //port进行字节序转换

	int ret=bind(sock,(struct sockaddr*)&address, sizeof( address));   //socket命名，注意要将专用地址进行强制类型转换。
	assert(ret!=-1);

	ret=listen(sock,backlog); 
	assert(ret!=-1);

	while(!stop)
	{
		sleep(1);
	}

	close(sock);
	return 0;
}

```

处于ESTABLISHED状态的连接只有backlog+1个。不同系统上，运行结果会有差异，但监听队列中完整连接的上限通常比backlog值大。

### 5.5接受连接

```c
#include<sys/types.h>
#include<sys/types.h>
/*从listen监听队列中接受一个连接。sockfd参数是执行过listen系统调用的监听socket，addr参数用来获取被接手连接的远端socket地址。成功返回一个新的连接socket,该socket唯一标识了被接受的这个连接，服务器可通过读写该socket来与被接受连接对应的客户段通信。失败返回-1并设置errno*/
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

accept只是从监听队列中取出连接，而不论连接处于何种状态，也不关心任何网络变化。

### 5.6发起连接

```c
#include<sys/types.h>
#include<sys/types.h>
/*服务器通过connect主动与服务器建立连接。serv_addr是服务器监听的socket地址。成功时返回0，一旦成功建立，sockfd就唯一标识了这个连接。失败则返回-1并设置errno。*/
int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);
```

两种常见的errno是

- ECONNREFUSED，目标端口不存在，连接被拒绝。
- ETIMEOUT，连接超时。（服务器返回SYN报文未收到）

### 5.7 关闭连接

```c
#include<unistd.h>
/*close系统调用并非总是立即关闭一个连接，而是将fd的引用计数-1。只有fd的引用计数为0时，才真正关闭连接。多进程程序中，一次fork系统调用默认将父进程中打开的socket的引用计数+1。*/
int close(int fd);
```

```c
#include<sys/socket.h>
/*立即终止连接。成功时返回0，失败返回-1并设置errno*/
int shutdown(int sockfd,int howto)
```

howto的值可取

|  可选值   |                             含义                             |
| :-------: | :----------------------------------------------------------: |
|  SHUT_RD  | 关闭sockfd上读的这一半，并该socket接收缓冲区中的数据都被丢弃 |
|  SHUT_WR  | 关闭sockfd上写的这一半，sockfd的发送缓冲区中的数据会在真正关闭连接前全部发送出去，应用程序不可再对该socket文件描述符执行写操作。这种情况下，连接处于半关闭状态。 |
| SHUT_RDWD |                   同时关闭sockfd上的读和写                   |

### 5.8 数据读写

#### 5.8.1 TCP数据读写

```c
#include<sys/types.h>
#include<sys/socket.h>
/*recv成功时返回实际读取的数据的长度，可能小于len，因此可能需要多次调用recv。recv可能返回0，这意味着通信对方已经关闭连接了，出错时返回-1并设置errno*/
ssize_t recv(int sockfd, void* buf, size_t len, int flags);
/*返回实际写入数据的长度，失败则返回-1并设置errno*/
ssize_t send(int sockfd, const void* buf, size_t len, int flags);
```

flags可取值

![](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图3.jpg)

```c
//客户端
#include<sys/types.h>
#include<sys/socket.h>
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
#include<arpa/inet.h>
#include<string.h>
#include<unistd.h>

int main(int argc, char* argv[])
{
	if(argc<=2)
	{
		printf("the paranmeter are ip and port");
	}

	const char* ip=argv[1];
	int port=atoi(argv[2]);

	int sockfd=socket(PF_INET, SOCK_STREAM, 0);

	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);

	if(connect(sockfd, (const struct sockaddr*) &servaddr, sizeof(servaddr))<0)
	{
		printf("connection failed\n");
	}
	else
	{
		const char* normal_data="123";
		const char* oob_data="abc";
		send(sockfd,normal_data,strlen(normal_data),0);
		send(sockfd,oob_data,strlen(oob_data),MSG_OOB);
		send(sockfd,normal_data,strlen(normal_data),0);
	}

	close(sockfd);

	return 0;
}
```

```c
//服务器
#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<errno.h>
#include<unistd.h>
#include<assert.h>

#define BUFFER_SIZE 1024

int main(int argc, char* argv[])
{
	if(argc<=2)
	{
		printf("parameter are ip and port\n");
	}

	const char* ip=argv[1];
	int port=atoi(argv[2]);
	int sockfd=socket(PF_INET,SOCK_STREAM,0);

	struct sockaddr_in servaddr;
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(port);
	inet_pton(AF_INET,ip,&servaddr.sin_addr);
	
	int ret=bind(sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr));
	assert(ret!=-1);

	ret=listen(sockfd, 5);
	assert(ret!=-1);

	struct sockaddr_in clientaddr;
	
	socklen_t addr_length=sizeof(clientaddr);
	int recvfd=accept(sockfd,(struct sockaddr*)&clientaddr, &addr_length);
	if(recvfd<0)
	{
		printf("errno is %d\n",errno);
	}
	else
	{
        /*注意,recv时读被接收的socket recvfd而不是sockfd*/
		char buffer[BUFFER_SIZE];
		memset(buffer,'\0',BUFFER_SIZE);
		ret=recv(recvfd,buffer,BUFFER_SIZE-1,0);
		printf("%d,normal data is %s\n",ret,buffer);

		memset(buffer,'\0',BUFFER_SIZE);
		ret=recv(recvfd,buffer,BUFFER_SIZE-1,MSG_OOB);
		printf("%d,oob data is %s\n",ret,buffer);

		memset(buffer,'\0',BUFFER_SIZE);
		ret=recv(recvfd,buffer,BUFFER_SIZE-1,0);
		printf("%d,normal data is %s\n", ret,buffer);
		close(recvfd);
	}
	close(sockfd);

	return 0;
}
/*
5,normal data is 123ab
1,oob data is c
3,normal data is 123
*/
```

#### 5.8.2 UDP数据读写

```c
#include<sys/types.h>
#include<sys/socket.h>
/*读取sockfd上的数据，每次读取数据都需要获取发送端的socket地址即src_addr所指的内容*/
ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
ssize_t sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
```

- flags参数以及返回值的含义均与send/recv系统调用的flags参数及返回值相同。
- recvfrom/sendto系统调用也可以用于STREAM的socket的数据读写。只需要把最后两个参数都设置为NULL以忽略发送端/接收端的socket地址。

#### 5.8.3 通用数据读写函数

可以同时用于TCP和UDP数据的读写。

```c
#include<sys/socket.h>
ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags);
ssize_t sendmsg(int sockfd, struct msghdr* msg, int flags);

struct msghdr
{
    void* msg_name;              /*socket地址，指向一个socket地址结构变量。在TCP协议中设置为NULL*/
    socklen_t msg_namelen;       /*socket地址长度*/
    struct iovec* msg_iov;       /*分散的内存块*/
    int msg_iovlen;              /*分散的内存块的数量，对于recvmsg而言，数据将被读取并存放在msg_iovlen块分散的内存中，称为分散读；对于sendmsg而言,msg_lovlen块分散内存中的数据将被一并发送，称为集中写*/
    void* msg_control;           /*指向辅助数据的起始位置*/
    socklen_t msg_controllen;    /*辅助数据的大小*/
    int msg_flags;               /*复制函数中的flags参数，并在调用过程更新，无需设定*/
};

struct iovec
{
    void* iov_base;    /*内存起始地址*/
    size_t iov_len;    /*这块内存的长度*/
};
```

### 5.9 带外标记

内核通知应用程序带外数据到达的两种常见方式是：

- I/O复用产生的异常事件
- SIGURG信号

```c
#include<sys/socket.h>
/*判断sockfd是否处于带外标记，即下一个被读取到的数据是否是带外数据。如果是，返回1，此时就可以利用MSG_OOB接收带外数据，否则返回0*/
int sockatmark(int sockfd);
```

### 5.10 地址信息函数

```c
#include<sys/socket.h>
/*获取sockfd对应的本端socket地址，并将其存储于address参数指定的内存中，该socket地址的长度则存储于address_len参数指向的变量中。若socket地址的长度大于address所指内存区的大小，那么该socket地址将被截断。成功返回0，失败返回-1*/
int getsockname(int sockfd, struct sockaddr* address, socklen_t* address_len);
/*获取远端socket地址*/
int getpeername(int sockfd, struct sockaddr* address, socklen_t* address_len);
```

