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
/*从listen监听队列中接受一个连接。sockfd参数是执行过listen系统调用的监听socket，addr参数用来获取被连接的远端socket地址。成功返回一个新的连接socket,该socket唯一标识了被接受的这个连接，服务器可通过读写该socket来与被接受连接对应的客户段通信。失败返回-1并设置errno*/
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

accept只是从监听队列中取出连接，而不论连接处于何种状态，也不关心任何网络变化。

### 5.6发起连接

```c
#include<sys/types.h>
#include<sys/socket.h>
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

![图3](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图3.jpg)



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

### 5.11 socket选项

专门用来读取和设置socket文件描述符属性的方法。

```c
#include<sys/socket.h>
/*level指定要操作哪个协议的选项，如IPv4,IPv6,TCP等。option_name指定选项的名字。成功时返回0，否则返回-1并设置errno*/
int getsockopt(int sockfd, int level, int option_name, void* option_value, socklen_t* restrict option_len);
int setsockopt(int sockfd, int level, int option_name, const void* option_value, socklen_t option_len);
```

![图4](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图4.jpg)

`对服务器而言，有部分socket选项只能在调用listen系统调用前针对监听socket设置才有效。对客户端而言，这些socket选项则应该在调用connect函数之前设置。`

#### 5.11.1 SO_REUSEADDR选项

```C
//socket
int reuse=1;
setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
//bind
```

此外也可以通过修改内核参数/proc/sys/net/ipv4/tcp_tw_recycle来快速回收被关闭的socket，从而使TCP连接根本不进入TIME_WAIT状态，劲儿允许应用程序立即重用本地的socket地址。

#### 5.11.2 SO_RCVBUF和SO_SNDBUF

SO_RCVBUF和SO_SNDBUF选项分别表示TCP接收缓冲区和发送缓冲区的大小。当我们使用setsockopt来设置TCP的接收缓冲区和发送缓冲区的大小时，`系统都会将其值加倍`，并且`不得小于某个最小值`。一般来说，接收缓冲区的最小值是256字节，发送缓冲区的最小值是2048字节。此外我们可以直接修改内核参数/proc/sys/net/ipv4/tcp_remem和/proc/sys/ net/ipv4/tcp_wmem来强制TCP接收缓冲区和发送缓冲区的大小没有最小值限制。

#### 5.11.3 SO_RCVLOWAT和SO_SNDLOWAT

SO_RCVLOWAT和SO_SNDLOWAT选项分别表示TCP接收缓冲区和发送缓冲区的低水位标记。它们一般被I/O复用系统调用用来判断socket是否可读或可写。当TCP接收缓冲区中可读数据的总数大于其低水位标记时，I/O复用系统调用将通知应用程序可以从对应的socket上读取数据；当TCP发送缓冲区中的空闲空间大于其低水位标记时，I/O复用系统调用将通知应用程序可以往对应的socket上写入数据。

默认情况下，就收缓冲区和发送缓冲区的低水位标记均为1。

#### 5.11.4 SO_LINGER

用于控制close系统调用在关闭TCP连接时的行为。当我们使用close系统调用来关闭一个socket时，close将立即返回，TCP模块负责把该socket对应的TCP发送缓冲区中残留的数据发送给对方。

```C
#include<sys/socket.h>
struct linger
{
    int l_onoff;           /*开启（非0）关闭（0）*/
    int l_linger;          /*滞留时间*/
};
```

- l_onoff=0，SO_LINGER不起作用。
- l_onoff不等于0，l_linger=0，close系统调用立即返回，TCP模块将丢弃被关闭的socket对应的TCP发送缓冲区中的残留数据，同时给对方发送一个RST。(异常终止)
- l_onoff不等于0，linger>0。close行为取决于两个条件：被关闭的socket对应的TCP发送缓冲区中是否还有残留的数据；socket是阻塞的还是非阻塞的。
  - 阻塞的socket，close将等待一段长为l_linger时间，直到TCP模块发送完所有残留数据并得到对方的确认。若这段时间内TCP模块没有发送完残留数据并得到对方的确认，那么close系统调用将返回-1并设置errno为EWOULDBLOCK。
  - 非阻塞的socket，close立即返回。根据返回值和errno来判断残留数据是否已经发送完毕。

### 5.12 网络信息API

`不可重入函数：如果我们使用静态变量，导致产生中断调用别的函数的过程中可能还会调用这个函数，于是原来的静态变量被再在这里改变了，然后返回主体函数，用着的那个静态变量就被改变，导致错误。`

#### 5.12.1 gethostbyname和gethostbyaddr

```c
#include<netdb.h>
/*根据主机名获取主机完整信息，通常先在/etc/hosts配置文件中查找主机，如果没有找到再去访问DNS服务器*/
struct hostent* gethostbyname(const char* name);
/*type合法取值包括AF_INET和AF_INET6*/
struct hostent* gethostbyaddr(const void* addr, size_t len, int type);

struct hostnet
{
    char* h_name;          /*主机名*/
    char** h_aliases;      /*主机别名列表，可能有多个*/
    int h_addrtype;        /*地址类型（地址簇）*/
    int h_length;          /*地址长度*/
    char** h_addr_list;    /*按网络字节序列出的主机IP地址列表*/
};
```

#### 5.12.2 getservbyname 和 getservbyport

```c
/*实际都是通过读取/etc/services文件来获取服务的信息*/
#include<netdb.h>
/*proto指定服务类型tcp/udp/null*/
struct servent* getservbyname(const char* name, const char* proto);
struct servent* getservbyport(int port, const char* proto);

struct sevent
{
    char* s_name;        /*服务名称*/
    char** s_aliases;    /*服务的别名列表，可能有多个*/
    int s_port;          /*端口号*/
    char* s_proto;       /*服务类型，tcp/udp*/
};
```

#### 5.12.3 getaddrinfo

5.12.1和5.12.2中的4个函数都是不可重入的（`非线性安全`)。可重入的版本是在原函数名尾部加上_r。

getaddrinfo既能通过主机名获得IP地址(内部调用gethostbyname函数)，也能通过服务名获得端口号(内部调用getservbyname函数)。是否可重入取决于其内部调用的两个函数是否是可重入版本。

```c
#include<stdio.h>
/*hostname可以接收主机名，也可以接收字符串表示的IP地址。service可以接收服务名，也可以接收字符串表示的十进制端口号。hints参数是应用程序给getaddrinfo的一个提示，以对getaddrinfo的输出进行更精确的控制，可以被设置成null,表示允许getaddrinfo反馈任何可用的结果。result指向一个链表，该链表用于存储getaddrinfo反馈的结果。*/
int getaddrinfo(const char* hostname, const char* service, const struct addrinfo* hints, struct addrinfo** result);

struct addrinfo
{
    int ai_flags;
    int ai_family;            /*地址簇*/
    int ai_socktype;          /*服务类型，SOCK_STREAM 或SOCK_DGRAM*/
    int ai_protocol;          /*指具体的网络协议，其含义和socket系统调用的第三个参数相同，通常被设置为0*/
    socklen_t ai_addrlen;     /*socket地址ai_addr长度*/
    char* ai_canonname;       /*主机别名*/
    struct sockaddr* ai_addr; /*指向socket地址*/
    struct addrinfo* ai_next; /*指向下一个sockinfo结构的对象*/
};
```

![图5](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图5.jpg)



当我们使用hints参数时，可以设置其ai_flags，ai_family，ai_socktype和ai_protocol四个字段，其他字段则必须设置为NULL。

```c
struct addrinfo hints;
struct addrinfo* res;
bzero(&hints,sizeof(hints));
hints.ai_socktype=SOCK_STREAM;
getaddrinfo("ernest-laptop","daytime",&hints,&res);
```

`getaddrinfo会隐式的分配堆内存（res原本没有合法内存）`。因此调用结束后必须手动释放内存。

```c
#include <netdb.h>
void freeaddrinfo(struct addrinfo* res)
```

#### 5.12.4 getnameinfo

可以通过socket地址同时获得以字符串表示的主机名（使用gethostbyaddr）和服务名（getservbyport）。

```c
#include <netdb.h>
/*host存储返回的主机名，serv存储返回的服务名*/
int getnameinfo(const struct sockaddr* sockaddr, socklen_t addrlen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags);
```

![图6](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图6.jpg)

getaddrinfo和getnameinfo函数成功返回0，失败则返回错误码，可能的错误码有：

![图7](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图7.jpg)

```c
#include<netdb.h>
/*能将数值错误码errno转换成易读的字符串形式*/
const char* gai_strerror(int error);
```

## 第6章 高级I/O函数

### 6.1 pipe函数

可用于创建一个管道，以实现进程间通信。

```c
#include<unistd.h>
/*该函数成功时返回0，并将一对打开的文件描述符填入其参数指向的数组。如果失败，则返回-1并设置errno*/
int pipe(int fd[2]);
```

- fd[0]和fd[1]构成管道的两端，往fd[1]写入的数据可以从fd[0]读出。`fd[0]只用于读，fd[1]只用于写`。`如果要实现双向的数据传输，应该使用两个管道`。
- 默认情况下这一对文件描述符都是阻塞的。
- 如果管道的写端文件描述符fd[1]的引用计数减少至0，则该管道的fd[0]的read操作将返回0（读到了EOF)。反之fd[0]的引用计数减少至0，则fd[1]的write操作将失败，并引发SIGPIPE信号。
- 管道内部传输的数据是字节流。管道本身有一个容量限制，默认是65535字节。可以使用fcntl来修改管道容量。

```c
#include<sys/types.h>
#include<sys/socket.h>
/*可以方便的创建双向管道。domain只可以使用AF_UNIX。创建的这一对文件描述符都是即可读又可写的。成功时返回0，失败时返回-1并设置errno*/
int sockpair(int domain, int type, int protocol, int fd[2]);
```

### 6.2 dup函数和dup2函数

把标准输入重定向到一个文件，或把标准输出重定向到一个网络连接。可以通过下面的用于复制文件描述符的函数来实现。

```c
#include<unistd.h>
/*创建一个新的文件描述符，该新文件描述符和原有文件描述符file_descriptor指向相同的文件、管道或网络连接。并且dup返回的文件描述符总是取系统当前可用的最小整数值*/
int dup(int file_descriptor);
/*它将返回第一个不小于file_descriptor_two的整数值*/
int dup2(int file_descriptor_one, int file_descriptor_two);
/*失败时返回-1并设置errno*/
```

`dup和dup2创建的文件描述符并不继承源文件描述符的属性。`

```c
//CGI基本工作原理
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int main( int argc, char* argv[] )
{
    if( argc <= 2 )
    {
        printf( "usage: %s ip_address port_number\n", basename( argv[0] ) );
        return 1;
    }
    const char* ip = argv[1];
    int port = atoi( argv[2] );

    struct sockaddr_in address;
    bzero( &address, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, ip, &address.sin_addr );
    address.sin_port = htons( port );

    int sock = socket( PF_INET, SOCK_STREAM, 0 );
    assert( sock >= 0 );

    int ret = bind( sock, ( struct sockaddr* )&address, sizeof( address ) );
    assert( ret != -1 );

    ret = listen( sock, 5 );
    assert( ret != -1 );

    struct sockaddr_in client;
    socklen_t client_addrlength = sizeof( client );
    int connfd = accept( sock, ( struct sockaddr* )&client, &client_addrlength );
    if ( connfd < 0 )
    {
        printf( "errno is: %d\n", errno );
    }
    else
    {
        close( STDOUT_FILENO ); //关闭标准输出
        dup( connfd );
        printf( "abcd\n" );     //abcd将不会输出到屏幕上，而会直接发送到与用户连接的socket上。
        close( connfd );
    }

    close( sock );
    return 0;
}
```

### 6.3 readv函数和writev函数

```c
#include<sys/uio.h>
/*分散读，count是vector数组的长度*/
ssize_t readv(int fd,const struct iovec* vector, int count);
/*集中写*/
ssize_t writev(int fd, const struct iovec* vector, int count);
//成功时返回读出/写入fd的字节数，失败则返回-1并设置errno
```

服务器HTTP应答。

```c
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<assert.h>
#include<errno.h>
#include<string.h>
#include<stdbool.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<sys/uio.h>

#define BUFFER_SIZE 1024
static const char* status[2]={"200 OK", "500 Internal server error"};
int main(int argc, char* argv[])
{
	if(argc<=3)
	{
		printf("the parameter are ip port and file path \n");
		return 1;
	}

	const char* ip=argv[1];
	int port=atoi(argv[2]);
	char* file_path=argv[3];

	struct sockaddr_in servaddr;
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(port);
	inet_pton(AF_INET,ip,&servaddr.sin_addr);

	int sockfd=socket(PF_INET,SOCK_STREAM,0);
	assert(sockfd!=-1);

	int ret=bind(sockfd,(struct sockaddr*)&servaddr, sizeof(servaddr));
	assert(ret!=-1);

	ret=listen(sockfd,5);
	assert(ret!=-1);

	struct sockaddr_in client;
	socklen_t clientlen=sizeof(client);
	int confd=accept(sockfd,(struct sockaddr*)&client,&clientlen);

	if(confd<0)
	{
		printf("errno is:%d \n",errno);

	}
	else
	{
		char head_buf[BUFFER_SIZE];   //保存HTTP状态行、头部字段和一个空行。
		memset(head_buf,'\0',BUFFER_SIZE);

		char* file_buf;         //存放文件内容
		struct stat file_stat;  //获取目标文件属性
        
		bool valid=true;        //记录文件是否有效
		int len=0;              //记录head_buf已经使用的字节数

		if(stat(file_path,&file_stat)<0)  //目标文件不存在
		{
			valid=false;
		}
		else
		{
			if(S_ISDIR(file_stat.st_mode)) //目标文件是一个目录
			{
				valid=false;
			}
			else if(file_stat.st_mode & S_IROTH) //当前用户有读取目标文件的权限
			{
				int fd=open(file_path,O_RDONLY);
				file_buf=new char[file_stat.st_size+1];
				memset(file_buf,'\0', file_stat.st_size+1);
				if(read(fd,file_buf,file_stat.st_size)<0)
				{
					valid=false;
				}
			}
			else
			{
				valid=false;
			}
		}
        
        //目标文件有效，正常HTTP应答
		if(valid)
		{
			ret=snprintf(head_buf,BUFFER_SIZE-1,"%s%s \r\n", "HTTP/1.1", status[0]);
			len+=ret;
			ret=snprintf(head_buf+len, BUFFER_SIZE-1-len, "Content-Length: %d\r\n", file_stat.st_size);
			len+=ret;
			ret=snprintf(head_buf+len, BUFFER_SIZE-1-len, "%s","\r\n");

			struct iovec iv[2];
			iv[0].iov_base=head_buf;
			iv[0].iov_len=strlen(head_buf);
			iv[1].iov_base=file_buf;
			iv[1].iov_len=file_stat.st_size;

			ret=writev(confd, iv,2);
		}
        //目标文件无效
		else
		{
			ret=snprintf(head_buf, BUFFER_SIZE-1, "%s %s \r\n", "HTTP/1.1", status[1]);
			len+=ret;
			ret=snprintf(head_buf, BUFFER_SIZE-1-len, "%s","\r\n");
			send(confd, head_buf, strlen(head_buf),0);
		}
		close(confd);
		delete [] file_buf;
	}

	close(sockfd);
	return 0;
}
```

### 6.4 sendfile函数

在两个文件描述符之间直接传递数据（`完全在内核中操作`），零拷贝。

```c
#include<sys/sendfile.h>
/*in_fd待读出内容的文件描述符，out_fd待写入内容的文件描述符。offset参数指定从读入文件流的哪个位置开始读。如果为空，则使用读入文件流默认的起始位置。count传输字节数。成功时返回字节数，失败则返回-1并设置errno。*/
ssize_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count);
```

`in_fd必须指向真实的文件，不能是socket和管道。out_fd必须是socket。`

```c
//省略6-2建立socket的步骤，只保留关于文件的部分
int filefd=open(file_path,ORDONLY);
assert(filefd>0);
struct stat stat_buf:
fstat(filefd,&stat_buf);

if(confd<0)
    printf("errno is: %d\n",errno);
else
{
    sendfile(confd,filefd,NULL,stat_buf.st_size);
    close(confd);
}
```

6-3没有为目标文件分配任何用户空间的缓存，也没有执行读取文件的操作，但同样实现了文件的发送，效率显然高很多。

### 6.5 mmap函数和munmap函数

mmap函数用于申请一段内存空间，可以将这段内存作为进程间通信的共享内存，也可以直接将文件映射到其中。

munmap函数释放由mmap创建的内存空间。

```c
#include<sys/mman.h>
/*start允许用户使用某个特定的地址作为这段内存的起始地址。如果被设置为NULL,则系统自动分配一个地址。length指定内存段的长度。prot用来设置内存段的访问权限。fd是被映射文件对应的文件描述符,通常通过open系统调用获得。offset参数设置从文件的何处开始映射。*/
void* mmap(void* start, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void* start, size_t length);
/*mmap函数成功时返回指向目标内存区域的指针，失败则返回MAP_FAILED((void*)-1)并设置errno。munmap函数成功时返回0,失败则返回-1并设置errno*/
```

prot可以取一下几个值得按位或

- PROT_READ，内存段可读。
- PROT_WRITE，内存段可写。
- PROT_EXEC，内存段可执行。
- PROT_NONE，内存段不能被访问。

flags参数控制内存段内容被修改后程序得行为。可以设置成下表中得某些值得按位或（MAP_SHARED和MAP_PRIVATE是互斥得，不能同时指定）。

![图8](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图8.jpg)

### 6.6 splice函数

splice函数用于在两个文件描述符直接移动数据，也是零拷贝操作。

```c
#include<fcntl.h>
/*fd_in参数是待输入数据的文件描述符。如果fd_in是一个管道文件描述符，那么off_in参数必须设置为NULL。如果fd_in不是一个管道文件描述符，那么off_in表示从输入数据流的何处开始读取数据。若此时off_in被设置为NULL，则表示从输入数据流的当前偏移位置读入。fd_out/off_out月fd_out/off_in相同。len指定移动数据的长度，flags参数控制数据如果移动。
成功时返回移动字节的数量，失败时返回-1并设置errno。*/
ssize_t splice(int fd_in, loff_t* off_in, int fd_out, loff_t* off_out, size_t len, unsigned int flags);
```

flags可以被设置为表中某些值的按位或。

![图9](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图9.jpg)

使用splice函数时，fd_in和fd_out必须至少有一个是管道文件描述符。

常见的errno

![图10](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图10.jpg)

```c
//实现一个零拷贝服务器（将客户端发送的数据原样返回给客户端.
//将客户端的内容读入到pipefd[1]中，然后将pipefd[0]中读出该内容到客户端。
int pipefd[2];
ret=pipe(pipefd);
ret=splice(confd,NULL,pipefd[1],NULL,32768, SPLICE_F_MORE | SPLICE_F_MOVE);
assert(ret!=-1);
ret=splice(pipefd[0],NULL,confd,NULL,32768, SPLICE_F_MORE | SPLICE_F_MOVE);
assert(ret!=-1);
close(confd);
```

### 6.7 tee函数

tee函数在两个`管道文件描述符`之间复制数据，也是零拷贝操作。它不消耗数据，因此源文件描述符上的数据仍然可以用于后续的读操作。

```c
//成功时返回两个文件描述符之间复制的数据数量，返回0表示没有复制任何数据。失败时返回-1并设置errno。
#include<fcntl.h>
ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
```

```c
//tee程序(同时输出数据到终端和文件的程序)
//为什么只用一个管道就会报错
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

int main( int argc, char* argv[] )
{
	if ( argc != 2 )
	{
		printf( "usage: %s <file>\n", argv[0] );
		return 1;
	}
	int filefd = open( argv[1], O_CREAT | O_WRONLY | O_TRUNC, 0666 );
	assert( filefd > 0 );

	int pipefd_stdout[2];
        int ret = pipe( pipefd_stdout );
	assert( ret != -1 );

	int pipefd_file[2];
        ret = pipe( pipefd_file );
	assert( ret != -1 );

	ret = splice( STDIN_FILENO, NULL, pipefd_stdout[1], NULL, 32768, SPLICE_F_MORE | SPLICE_F_MOVE );
	assert( ret != -1 );
	ret = tee( pipefd_stdout[0], pipefd_file[1], 32768, SPLICE_F_NONBLOCK ); 
	assert( ret != -1 );
	ret = splice( pipefd_file[0], NULL, filefd, NULL, 32768, SPLICE_F_MORE | SPLICE_F_MOVE );
	assert( ret != -1 );
	ret = splice( pipefd_stdout[0], NULL, STDOUT_FILENO, NULL, 32768, SPLICE_F_MORE | SPLICE_F_MOVE );
	assert( ret != -1 );

	close( filefd );
        close( pipefd_stdout[0] );
        close( pipefd_stdout[1] );
        close( pipefd_file[0] );
        close( pipefd_file[1] );
	return 0;
}
```

### 6.8 fcntl函数

fcntl提供了对文件描述符的各种控制操作。

```c
#include<fcntl.h>
// fd参数是被操作的文件描述符，cmd参数指定执行何种类型的操作。根据操作类型的不同，该函数可能还需要第三个可选参数arg。
int fcntl(int fd, int cmd, ...)
```

fcntl函数支持的常用操作及其参数。

![图11](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图11.jpg)

![图12](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图12.jpg)

在网络编程中，fcntl函数通常用来将一个文件描述符设置为非阻塞的。

```c
int setnonblocking(int fd)
{
    int old_option=fcntl(fd, F_GETFL); /*获取文件描述符旧的状态标志*/
    int new_option=old_option | O_NONBLOCK; /*设置非阻塞标志*/
    fcntl(fd, F_SETFL, new_option);
    return old_option; /*返回文件描述符旧的状态标志，以便日后恢复该状态标志*/
}
```

此外，SIGIO和SIGURG这两个信号与其他Linux信号不同，他们必须与某个文件描述符相关联方可使用：当被关联的文件描述符可读或可写时，系统将触发SIGIO信号；当被关联的文件描述符(而且必须是一个socket)上有带外数据可读时，系统将触发SIGURG信号。将信号和文件描述符关联的方法，就是使用fcntl函数为目标文件描述符指定宿主进程或进程组，那么被指定的宿主进程或进程组将捕获这两个信号。使用SIGIO时，还需要利用fcntl设置其O_ASYNC标志。