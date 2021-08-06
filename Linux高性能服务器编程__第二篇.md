 

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

## 第7章 Linux服务器程序规范

- Linux服务器程序一般以后台进程形式运行。后台进程又称守护进程。它没有控制终端，因而也不会以外接收到用户输入。守护进程的父进程通常是init进程。
- Linux服务器程序通常有一套日志系统。大部分后台进程都在/var/log目录下有自己的日志文件。
- Linux服务器程序一般以某个专门的非root身份运行。
- Linux服务器程序通常是可配置的。可以通过配置文件来管理。配置文件一般存放在/etc目录下。
- Linux服务器进程通常会在启动的时候生成一个PID文件并存入/var/run目录总。
- Linux服务器程序通常需要考虑系统资源和限制，以预测自身能承受多大符合。

### 7.1 日志

#### 7.1.1 Linux日志系统

![图13](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图13.jpg)

默认情况下，调试信息会保存至/var/log/debug文件，普通信息保存至/var/log/messages文件，内核消息则保存至/var/log/kern.log文件。不过，日志信息具体如何分发，可以在rsyslogd的配置文件中设置。rsyslogd的主配置文件是/etc/rsyslog.conf。

#### 7.1.2 syslog函数

应用程序使用syslog函数与rsyslogd守护进程通信。

```c
#include<syslog.h>
/*该函数采用可变参数(第二个，第三个参数)来结构化输出。priority参数是所谓的设施值与日志级别的按位或。设施值得默认值是LOG_USER。*/
void syslog(int priority, const char* message, ...);

//日志级别
#include<syslog.h>
#define LOG_EMERG            0 /*系统不可用*/
#define LOG_ALERT            1 /*报警，需要立即采取动作*/
#define LOG_CRIT             2 /*非常严重的情况*/
#defien LOG_ERR              3 /*错误*/
#define LOG_WARNING          4 /*警告*/
#define LOG_NOTICE           5 /*通知*/
#define LOG_INFO             6 /*信息*/
#define LOG_DEBUG            7 /*调试*/

#include<syslog.h>
/*此函数可以改变syslog的默认输出方式，进一步结构化日志内容。ident参数指定的字符串将被添加到日志消息的日期和时间之后，它通常被设置为程序的名字。logpot参数对后续syslog调用的行为进行配置，它可以取下列值的按位或。facility参数可用来修改syslog函数中的默认设施值*/
void openlog(const char* ident, int logopt, int facility);

//logopt
#define LOG_PID         0X01 /*在日志消息中包含程序PID*/
#define LOG_CONS        0X02 /*如果消息不能记录到日志文件，则打印至终端*/
#define LOG_ODELAY      0X04 /*延迟打开日志功能直到第一次调用syslog*/
#define LOG_NDELAY      0x08 /*不延迟打开日志功能*/
```

此外，日志的过滤也很重要。设置日志掩码，`使日志级别大于日志掩码的日志信息被系统忽略`。

```c
#include<syslog.h>
/*maskpri参数指定日志掩码值。该函数始终会成功，它返回调用进程先前的日志掩码值*/
int setlogmask(int maskpri);

#include<syslog.h>
/*关闭日志功能*/
void closelog();
```

### 7.2 用户信息

#### 7.2.1 UID, EUID, GID, EGID

```c
#include<sys/types.h>
#include<unistd.h>
uid_t getuid();
uid_t geteuid();
uit_t getgid();
uit_t getegid();
int setuid(uid_t uid);
int seteuid(uid_t uid);
int setgid(gid_t gid);
int setgid(gid_t gid);
```

一个进程有两个用户ID: UID和EUID。EUID存在的目的是方便资源访问：它使得运行程序的用户拥有该程序的有效用户的权限。有效用户为root的进程称为特权进程。

#### 7.2.2 切换用户

```c
//将root身份启动的进程切换为一个以普通用户身份运行
static bool switch_to_user( uid_t user_id, gid_t gp_id )
{
    if ( ( user_id == 0 ) && ( gp_id == 0 ) )
    {
        return false;
    }

    gid_t gid = getgid();
    uid_t uid = getuid();
    if ( ( ( gid != 0 ) || ( uid != 0 ) ) && ( ( gid != gp_id ) || ( uid != user_id ) ) )
    {
        return false;
    }

    if ( uid != 0 )
    {
        return true;
    }

    if ( ( setgid( gp_id ) < 0 ) || ( setuid( user_id ) < 0 ) )
    {
        return false;
    }

    return true;
}
```

### 7.3 进程间关系

#### 7.3.1 进程组

Linux下每个进程都隶属于一个进程组，因此它们出了PID信息外，还有进程组ID (PGID) 。

```c
#include<unistd.h>
pid_t getpgid(pid_t pid);

#include<unistd.h>
int setpgid(pid_t pid, pid_t pgid);
```

每个进程组都有一个首领进程，其PGID和PID相同。如果pid和pgid相同，则由pid指定的进程将被设置为进程组首领；如果pid为0，则表示设置当前进程的PGID为pgid；如果pgid为0，则使用pid作为目标PGID。

`一个进程只能设置自己或其子进程的PGID。并且当子进程调用exec系列函数后，我们也不能再在父进程中对它设置PGID。`

#### 7.3.2 会话

一些有关联的进程组将形成一个会话。

```c
#include<unistd.h>
/*创建一个会话。成功返回新的进程组的PGID，*/
pid_t setsid(void);
```

该函数不能由进程组的首领进程调用。对于非族首领的进程，调用该函数不仅创建新会话，而且由如下额外效果：

- 调用进程成为会话的首领，此时该进程是新会话的唯一成员。
- 新建一个进程组，其PGID就是调用进程的PID，调用进程成为该组的首领。
- 调用进程将甩开终端。

Linux进程并未提供所谓会话ID的概念，但Linux系统认为它等于会话首领所在的进程组的PGID。

```c
#include<unistd.h>
pid_t getsid(pid_t pid);
```

#### 7.3.3 用ps命令查看进程关系

### 7.4 系统资源限制

Linux系统资源限制可以通过如下一对函数来读取和设置。

```c
#include<sys/resource.h>
/*成功返回0，失败返回-1并设置errno*/
int getrlimit(int resource, struct rlimit *rlim);
int setrlimit(int resource, const struct rlimit *rlim);

/*rlim_t是一个整数类型，它描述资源级别。rlim_cur成员指定资源的软限制，rlim_max成员指定资源的硬限制。*/
struct rlimit
{
    rlim_t rlim_cur;
    rlim_t rlim_max;
}
```

软限制是一个建议性的、最好不要超越的限制，如果超越的话，系统可能向进程发送信号以终止其运行。硬限制一般是软限制的上限。普通程序可以减小应限制，而只有以root身份运行的程序才能增加硬限制。

此外我们可以使用ulimit命令修改当前shell环境下的资源限制；也可以通过修改配置文件来改变系统资源限制。

![图14](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图14.jpg)

### 7.5 改变工作目录和根目录

Web服务器的逻辑根目录并非文件系统的根目录/，而是站点的根目录(一般是/var/www)。

```c
#include<unistd.h>
/*获取进程当前工作目录。buf参数指向的内存用于存储进程当前工作目录的绝对路径，其大小由size参数指定。如果当前工作目录的绝对路径长度(加上"\0")超过了size，则getcwd将返回NULL，并设置errno为ERANGE。若buf为NULL并且size非0，则getcwd可能在内部使用malloc动态分配内存，并将进程的当前工作目录存储在其中。此时，我们必须自己来释放getcwd在内部创建的这块内存。getcwd函数成功时返回一个指向目标存储区的指针，失败则返回NULL并设置errno*/
char* getcwd(char* buf, size_t size);
/*改变进程工作目录。path指定要切换到的目标目录。成功时返回0，失败时返回-1并设置errno*/
int chdir(const char* path);
/*改变进程根目录。chroot并不改变进程的当前工作目录，调用chroot之后，我们仍需要使用chdir(“/”)来将工作目录切换至新的根目录*/
int chroot(const char* path);
```

### 7.6 服务程序后台化

```c
bool daemonize()
{
    /*创建子进程，关闭父进程，这样可以使程序在后台运行*/
    pid_t pid = fork();
    if ( pid < 0 )
    {
        return false;
    }
    else if ( pid > 0 )
    {
        exit( 0 );                   //关闭父进程
    }
    
    /*设置文件权限掩码。当进程创建新文件(使用open(const char *pathname, int flags, mode_t mode)系统调用)时，文件的权限将是mode&0777*/
    umask( 0 );  //0代表拥有所有权限，创建文件和目录的最大权限依然是0777
    
    /*创建新的会话，设置本进程为进程组的首领*/
    pid_t sid = setsid();
    if ( sid < 0 )
    {
        return false;
    }
    
    /*切换工作目录*/
    if ( ( chdir( "/" ) ) < 0 )
    {
        /* Log the failure */
        return false;
    }
    
    /*关闭标准输入设备，标准输出设备和标准错误输出设备*/
    close( STDIN_FILENO );
    close( STDOUT_FILENO );
    close( STDERR_FILENO );
    
    /*关闭其他已经打开的文件描述符，代码省略*/
    /*将标准输入、标准输出和标准错误输出都定向到/dev/null文件*/
    open( "/dev/null", O_RDONLY );
    open( "/dev/null", O_RDWR );
    open( "/dev/null", O_RDWR );
    return true;
}

#include<unistd.h>
/*Linux提供的相同功能的库函数。nochdir参数用于指定是否改变工作目录，如果给它传递0，则工作目录将被设置为"/",否则继续使用当前工作目录。noclose参数为0时，标准输入、标准输出和标准错误输出都被重定向到/dev/null文件，否则依然使用原来的设备。成功时返回0，失败则返回-1并设置errno。*/
int daemon(int nochdir, int noclose);
```

## 第8章 高性能服务器程序框架

服务器主要解构为如下三个主要模块：

- I/O处理单元
- 逻辑单元
- 存储单元

### 8.1 服务器模型

#### 8.1.1 C/S模型

![图15](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图15.jpg)

优：非常适合资源相对集中的场合，并且实现简单。

缺：服务器是通信的中心，访问量过大时，可能所有客户都将得到很慢的响应。

#### 8.1.2 P2P模型

P2P模型比C/S模型更符合网络通信的实际情况。云计算机群可以看作P2P模型的一个典范。实际使用的PSP模型通常带有一个专门的发现服务器。这个发现服务器通常还提供查找服务，使每个客户都能尽快地找到自己需要的资源。

### 8.2 服务器编程框架

![图16](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图16.jpg)

|     模块     |       单个服务器程序       |          服务器机群          |
| :----------: | :------------------------: | :--------------------------: |
| I/O处理单元  | 处理客户连接，读写网络数据 | 作为接入服务器，实现负载均衡 |
|   逻辑单元   |       业务进程或线程       |          逻辑服务器          |
| 网络存储单元 |   本地数据库、文件或缓存   |         数据库服务器         |
|   请求队列   |    各单元之间的通信方式    |  和服务器之间的永久TCP连接   |

I/O处理单元时服务器管理客户连接的模块。通常要完成一下工作。

- 等待并接受新的客户连接，接收客户数据。
- 将服务器响应数据返回给客户端。

一个逻辑单元通常时一个进程或线程。它分析并处理客户数据，然后将结果传递给I/O处理单元或者直接发送给客户端。

网络存储单元不是必须的，如ssh、telnet等登录服务就不需要这个单元。

请求队列是各单元之间的通信方式的抽象。I/O处理单元接收到客户请求时，需要以某种方式通知一个逻辑单元来处理该请求。同样，多个逻辑单元同时访问一个存储单元时，也需要采用某种机制来协调处理竞态条件。请求队列通常被实现为池的一部分。

### 8.3 I/O模型

- 阻塞I/O：无法立即完成会被OS挂起，直到事件发生为止。socket的基础API中，可能被阻塞的系统调用有accept, send, recv和connect。
- 非阻塞I/O：总是立刻返回，不管事件是否已经发生。如果没有立即发生，这些系统调用就返回-1。此时根据errno来区分是出错还是未完成。对accept, send和recv而言，未发生时errno通常被设置成EAGAIN或者EWOULDBLOCK；对connnect而言，errno则被设置成EINPROGRESS。

socket在创建时默认是阻塞的。

I/O复用是最常用的I/O通知机制。应用程序通过I/O复用函数向内核注册一组事件，内核通过I/O复用函数把其中就绪的事件通知给应用程序。Linux常用的I/O复用函数是select, poll和epoll_wait。I/O复用函数本身是阻塞的。它们能提高程序效率的原因在于它们具有同时监听多个I/O事件的能力。

SIGIO信号也可以用来报告I/O事件。

- 同步I/O模型：从理论上说，阻塞I/O、I/O复用和信号驱动I/O都是同步I/O模型。I/O的读写操作，都是在I/O事件发生之后，由应用程序来完成。
- 异步I/O模型：用户可以直接对I/O执行读写操作，这些操作告诉内核用户读写缓冲区的位置，以及I/O操作完成之后内核通知应用程序的方式。异步I/O的读写操作总是立即返回，而不论I/O是否是阻塞的。因为真正的读写操作已经由内核接管。

`同步I/O要求用户代码自行执行I/O操作，而异步I/O机制则由内核来执行I/O操作。`同步I/O向应用程序通知的是I/O就绪事件，而异步I/O向应用程序通知的是I/O完成事件。

### 8.4 两种高效的事件处理模式

服务器程序通常需要处理三类事件：I/O事件、信号及定时事件。

`同步I/O模型通常用于实现Reactor模式，异步I/O模型则用于实现Proactor模式。`

#### 8.4.1 Reactor模式

主线程只负责监听文件描述上是否有事件发生，有的话立刻将该事件通知工作线程。除此之外，主线程不做任何其他实质性的工作，都在工作线程中完成。

![图18](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图18.jpg)

工作线程从请求队列中取出事件后，将根据事件的类型来决定如何处理它，不区分读工作线程和写工作线程。

#### 8.4.2 Proactor模式

Proactor模式将所有I/O操作都交给主线程和内核来处理，工作线程仅仅负责业务逻辑。

![图17](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图17.jpg)

主线程中的epoll_wait调用仅能用来检测监听socket上的连接请求事件，而不能用来检测连接socket上的读写事件。

#### 8.4.3 模拟Proactor模式

可以使用同步I/O方式模拟出Proactor模式。原理是：主线程执行数据读写，读写完成之后，主线程向工作线程通知这一“完成事件”。那么从工作线程的角度来看，它们就直接获得了数据读写的结果，接下来只是对读写的结果进行逻辑处理。

![图19](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图19.jpg)

![图20](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图20.jpg)

### 8.5 两种高效的并发模式

#### 8.5.1 半同步/半异步模式

#### 8.5.2 领导者/追随者模式

### 8.6 有限状态机

### 8.7 提高服务器性能的其他建议

#### 8.7.1 池

#### 8.7.2 数据复制

#### 8.7.3 上下文切换和锁

## 第9章  I/O复用

I/O复用使得程序能同时监听多个文件描述符。在下列情况需要使用I/O复用技术。

- 客户端程序要同时处理多个socket。
- 客户端程序要同时处理用户输入和网络连接。
- TCP服务器要同时处理监听socket和连接socket。
- 服务器要同时处理TCP请求和UDP请求。
- 服务器要同时监听多个端口，或者处理多种服务。

I/O复用虽然能同时监听多个文件描述符，但它本身是阻塞的。如果要实现并发，只能使用多进程或多线程等编程手段。

### 9.1 select系统调用

#### 9.1.1 selectAPI

在一段指定时间内，监听用户感兴趣的文件描述符上的可读、可写和异常等事件。

```c++
#include<sys/select.h>
/*nfds参数指定被监听的文件描述符的总数。readfds,writefds和exceptfds参数分别指向可读、可写和异常等事件对应的文件描述符集合。应用程序调用select函数时，通过这3哥参数传入自己感兴趣的文件描述符。select调用返回时，内核将修改它们来通知应用程序哪些文件描述符已经就绪。
timeout参数用来设置select函数的超时事件。调用失败时timeout值是不确定的。如果timeout变量的tv_sec和tv_usec成员都传递0，则select将立即返回。如果给timeout传递NULL,则select将一直阻塞，直到某个文件描述符就绪。
select成功时返回就绪文件描述符的总数。如果在超时时间内没有任何文件描述符准备就绪，将返回0。失败时返回-1并设置errno。如果在select等待期间，程序接收到信号，则select立即返回-1，并设置errno为EINTR*/
int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);

/*fd_set结构体仅包含一个整型数组，该数组的每个元素的每一位标记一个文件描述符。fd_set能容纳的文件描述符数量由FD_SETSIZE指定，这就限制了select能同时处理的文件描述符的总量。我们使用下面的一些列宏来访问fd_set结构体中的位*/
#include<sys/select.h>
FD_ZERO(fd_set *fdset); //清除fdset的所有位
FD_SET(int fd, fd_set *fdset); //设置fdset的位fd
FD_CLR(int fd, fd_set *fdset); //清除fdset的位fd
int FD_ISSET(int fd, fd_set *fdset); //测试fdset的位fd是否被设置

struct timeval
{
    long tv_sec;   //秒数
    long tv_usec;  //微秒数
};
```

#### 9.1.2 文件描述符就绪条件

下列情况下socket可读

- socket内核接收缓存区中的字节数大于或等于其低水位标记SO_RCVLOWAT。此时我们可以无阻塞的读该socket，并且读操作返回的字节数大于0。
- socket通信的对方关闭连接。此时对该socket的读操作将返回0。
- 监听socket上由新的连接请求。
- socket上由未处理的错误。可以使用getsockopt来读取和清除该错误。

下列情况下socket可写

- socket内核发送缓存区中的可用字节数大于或等于其低水位标记SO_SNDLOWAT。此时可以无阻塞地写该socket，并且写操作返回的字节数大于0。
- socket的写操作被关闭。对写操作被关闭的socket执行写操作将触发一个SIGPIPE信号。
- socket使用非阻塞connect连接成功或失败之后。
- socket上有未处理的错误。

网络程序中，select能处理的异常情况只有一种：socket上接收到带外数据。

#### 9.1.3 处理带外数据

```c++
#include<stdio.h>
#include<string.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<assert.h>
#include<netinet/in.h>
#include<errno.h>
#include<sys/select.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>

int main(int argc, char* argv[])
{
	if(argc<=2)
	{
		printf("the parameter are ip and port\n");
		return 1;
	}
	
	const char* ip=argv[1];
	int port=atoi(argv[2]);
	
	struct sockaddr_in servadd;
	bzero(&servadd, sizeof(servadd));
	servadd.sin_family=AF_INET;
	servadd.sin_port=htons(port);
	
	int ret=inet_pton(AF_INET,ip, &servadd.sin_addr);
	
	int listenfd=socket(PF_INET, SOCK_STREAM, 0);
	assert(listenfd>=0);

	ret=bind(listenfd,(struct sockaddr*) &servadd, sizeof(servadd));
	assert(ret!=0);

	ret=listen(listenfd,5);
	assert(ret!=0);

	struct sockaddr_in clientadd;
	socklen_t client_addrlen=sizeof(clientadd);
	int connfd=accept(listenfd,(struct sockaddr*)& clientadd, &client_addrlen);
	
	if(connfd<0)
	{
		printf("errno is %d\n", errno);
		close(listenfd);
	}

	char buffer[1024];
	fd_set readfd;
	fd_set exceptionfd;
	FD_ZERO(&readfd);
	FD_ZERO(&exceptionfd);

	while(1)
	{
		memset(buffer,'\0',sizeof(buffer)-1);
        //每次调用select前都要重新设置文件描述符
		FD_SET(connfd, &readfd);
		FD_SET(connfd,&exceptionfd);
		ret=select(connfd,&readfd,NULL,&exceptionfd,NULL);
		if(ret<0)
		{
			printf("select failure\n");
			break;
		}
		
        //可读事件
		if(FD_ISSET(connfd, &readfd))
		{
			ret=recv(connfd, buffer, sizeof(buffer)-1,0);
			if(ret<=0)
				break;
			printf("get %d bytes normal data\n",ret);
		}
        //异常事件
		else if(FD_ISSET(connfd,&exceptionfd))
		{
			ret=recv(connfd, buffer, sizeof(buffer)-1,MSG_OOB);
			if(ret<=0)
				break;
			printf("get %d bytes oob data\n",ret);
		}
	}
	close(connfd);
	close(listenfd);
	return 0;
}
```

### 9.2 poll系统调用

poll系统调用和select类似，也是在指定事件内轮询一定数量的文件描述符，以测试其中是否有就绪者。

```c++
#include<poll.h>
/*
fds指定所有我们感兴趣的文件描述符上发生的可读、可写和异常等事件。
nfds指定被监听事件集合fds的大小。
timeout指定poll的超时值，单位是毫秒。timeout为-1时，poll调用将永远阻塞，直到某个事件发生，timeout为0，poll调用将立即返回。
返回值的含义同select相同。
*/
int poll(struct pollfd* fds, nfds_t nfds, int timeout);

struct pollfd
{
    int fd;            //文件描述符
    short events;      //注册的事件
    short revents;     //实际发生的事件，由内核填充
}
/*events成员告诉poll监听fd上的哪些事件，它是一系列事件的按位或；revents由内核修改，以通知应用程序fd上实际发生了哪些事件。*/

typedef unsigned long int nfds_t;
```

poll支持的事件类型有：

![图21](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图20.jpg)



![图22](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图21.jpg)

通常应用程序需要根据recv调用的返回值来区分socket上接收到的是有效数据还是对方关闭连接的请求，并作相应的处理。不过自Linux内核2.6.17开始，GNU为poll系统调用增加了一个POLLRDHUP事件，它在socket上接收到对方关闭连接的请求之后触发。`但使用POLLRDHUP事件时，我们需要在代码最开始处定义__GNU_SOURCE。`

### 9.3 epoll系列系统调用

#### 9.3.1 内核事件表

`epoll是Linux特有的I/O复用函数。`在实现和使用上与select，poll有很大差异。

- epoll使用一组函数完成任务。
- 把用户关心的文件描述符上的事件放在内核里的一个事件表中，无需每次调用都要重复传入文件描述符集或事件集。
- 需要使用一个额外的文件描述符，来唯一标识内核中的事件表。

```c++
#include<sys/epoll.h>
/*创建标识事件表的文件描述符*/
int epoll_create(int size);
/*fd参数是要操作的文件描述符，op指定操作类型。成功时返回0，失败时返回-1并设置errno。*/
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

/*epoll支持的事件类型和poll基本相同。标识epoll事件类型的宏是在poll对应的宏前加上E。但epoll有两个额外的事件类型，EPOLLET和EPOLLONESHOT
data用于存储用户数据。*/
struct epoll_event
{
    __uint32_t events; //epoll事件
    epoll_data_t data; //用户数据
}

/*fd指定事件从属的目标文件描述符，ptr成员可用来指定与fd相关的用户数据。但epoll_data是一个联合体，不可以同时使用其ptr成员和fd成员。如果将文件描述符和用户数据关联起来的话，可以放弃使用fd，在ptr指向的用户数据中包含fd。*/
typedef union epoll_data
{
    void* ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
}epoll_data_t;
```

op指定的操作类型有三种：

- EPOLL_CTL_ADD，往事件表中注册fd上的事件。
- EPOLL_CTL_MOD，修改fd上的注册事件。
- EPOLL_CTL_DEL，删除fd上的注册事件。

#### 9.3.2 epoll_wait函数

epoll_wait在一段超时时间内等待一组文件描述符上的事件。

```c++
#include<sys/epoll.h>
/*
成功时返回就绪的文件描述符的个数，失败时返回-1并设置errno。
epoll_wait函数如果检测到事件，就将所有就绪的事件从内核事件表(epfd)中复制到它的第二个参数events指向的数组中。这个数组只用于输出epoll_wait检测到的就绪事件。
*/
int epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout);
```

poll和epoll在使用上的差别。

```c++
int ret=poll(fds,MAX_EVENT_NUMBER,-1);
/*必须便利所有已注册文件默哀舒服并找到其中的就绪者，可以用ret做优化*/
for(int i=0; i<MAX_EVENT_NUMBER; ++i)
{
    if(fds[i].revents & POLLIN)
    {
        int sockfd=fds[i].fd;
        /*处理sockfd*/
    }
}

int ret=epoll_wait(epollfd, events, MAX_EVENT_NUMBER, -1);
/*event中一定是就绪事件*/
for(int i=0; i<ret; i++)
{
    int sockfd=events[i].data.fd;
    /*处理sockfd*/
}
```

#### 9.3.3 LT和ET模式

epoll对文件描述符的操作有两种模式，LT(Level Trigger, 电平触发模式)和ET(Edge Trigger, 边沿触发模式)。

- LT是默认的工作模式，epoll相当于一个效率较高的poll。当epoll_wait检测到其上有事件发生并将此事件通知应用程序后，应用程序可以不立即处理该事件。当应用程序下一次调用epoll_wait时，epoll_wait还会再次向应用程序通告此事件，直到该事件被处理。
- 当往epoll内核事件表中注册一个文件描述符上的EPOLLET事件时，epoll将以ET模式来操作该文件描述符。ET模式是epoll的高效工作模式。当epoll_wait检测到其上有事件发生并将此事件通知应用程序后，应用程序必须立即处理该事件，因为后续的epoll_wait调用将不再向应用程序通知这一事件。在很大程度上降低了同一个epoll事件被重复触发的次数。

```c++
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <pthread.h>

#define MAX_EVENT_NUMBER 1024
#define BUFFER_SIZE 10

int setnonblocking( int fd )
{
    int old_option = fcntl( fd, F_GETFL );
    int new_option = old_option | O_NONBLOCK;
    fcntl( fd, F_SETFL, new_option );
    return old_option;
}

void addfd( int epollfd, int fd, bool enable_et )
{
    epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN;
    if( enable_et )
    {
        event.events |= EPOLLET;
    }
    epoll_ctl( epollfd, EPOLL_CTL_ADD, fd, &event );
    setnonblocking( fd );
}

void lt( epoll_event* events, int number, int epollfd, int listenfd )
{
    char buf[ BUFFER_SIZE ];
    for ( int i = 0; i < number; i++ )
    {
        int sockfd = events[i].data.fd;
        if ( sockfd == listenfd )
        {
            struct sockaddr_in client_address;
            socklen_t client_addrlength = sizeof( client_address );
            int connfd = accept( listenfd, ( struct sockaddr* )&client_address, &client_addrlength );
            addfd( epollfd, connfd, false );  //connfd也要加入到内核事件表中
        }
        else if ( events[i].events & EPOLLIN )
        {
            printf( "event trigger once\n" );
            memset( buf, '\0', BUFFER_SIZE );
            int ret = recv( sockfd, buf, BUFFER_SIZE-1, 0 );
            if( ret <= 0 )
            {
                close( sockfd );
                continue;
            }
            printf( "get %d bytes of content: %s\n", ret, buf );
        }
        else
        {
            printf( "something else happened \n" );
        }
    }
}

void et( epoll_event* events, int number, int epollfd, int listenfd )
{
    char buf[ BUFFER_SIZE ];
    for ( int i = 0; i < number; i++ )
    {
        int sockfd = events[i].data.fd;
        if ( sockfd == listenfd )
        {
            struct sockaddr_in client_address;
            socklen_t client_addrlength = sizeof( client_address );
            int connfd = accept( listenfd, ( struct sockaddr* )&client_address, &client_addrlength );
            addfd( epollfd, connfd, true );
        }
        else if ( events[i].events & EPOLLIN )
        {
            printf( "event trigger once\n" );
            while( 1 )
            {
                memset( buf, '\0', BUFFER_SIZE );
                int ret = recv( sockfd, buf, BUFFER_SIZE-1, 0 );
                if( ret < 0 )  //对于非阻塞I/O，ret小于0， 可能出错可能事件没有立即发生
                {
                    if( ( errno == EAGAIN ) || ( errno == EWOULDBLOCK ) ) //事件没有立即发生
                    {
                        printf( "read later\n" );
                        break;
                    }
                    close( sockfd );  //出错
                    break;
                }
                else if( ret == 0 )  //对方关闭连接
                {
                    close( sockfd );
                }
                else
                {
                    printf( "get %d bytes of content: %s\n", ret, buf );
                }
            }
        }
        else
        {
            printf( "something else happened \n" );
        }
    }
}

int main( int argc, char* argv[] )
{
    if( argc <= 2 )
    {
        printf( "usage: %s ip_address port_number\n", basename( argv[0] ) );
        return 1;
    }
    const char* ip = argv[1];
    int port = atoi( argv[2] );

    int ret = 0;
    struct sockaddr_in address;
    bzero( &address, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, ip, &address.sin_addr );
    address.sin_port = htons( port );

    int listenfd = socket( PF_INET, SOCK_STREAM, 0 );
    assert( listenfd >= 0 );

    ret = bind( listenfd, ( struct sockaddr* )&address, sizeof( address ) );
    assert( ret != -1 );

    ret = listen( listenfd, 5 );
    assert( ret != -1 );

    epoll_event events[ MAX_EVENT_NUMBER ];
    int epollfd = epoll_create( 5 );
    assert( epollfd != -1 );
    addfd( epollfd, listenfd, true );

    while( 1 )
    {
        int ret = epoll_wait( epollfd, events, MAX_EVENT_NUMBER, -1 );
        if ( ret < 0 )
        {
            printf( "epoll failure\n" );
            break;
        }
    
        lt( events, ret, epollfd, listenfd );
        //et( events, ret, epollfd, listenfd );
    }

    close( listenfd );
    return 0;
}

```

`每个使用ET模式得文件描述符都应该是非阻塞的。`如果文件描述符是阻塞的，那么读或写操作将会因为没有后续的事件而一直处于阻塞状态。

#### 9.3.4 EPOLLONESHOT事件

对于注册了EPOLLONESHOT事件的文件描述符，操作系统最多触发其上注册的一个可读、可写或者异常事件，`且只触发一次`。除非我们使用epoll_ctl函数重置该文件描述符上注册的EPOLLONESHOT事件。

- 一个线程在处理某个socket时，其他线程不可能有机会操作该socket。
- 注册了EPOLLONESHOT事件的socket一旦被某个线程处理完毕，该线程就应该立即重置这个socket上的EPOLLONESHOT事件，以确保这个socket下一次可读时，其EPOLLIN事件能被触发。

```c++
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<assert.h>
#include<sys/epoll.h>
#include<fcntl.h>
#include<pthread.h>
#include<fcntl.h>
#include<sys/types.h>
#include<unistd.h>

#define MAX_EVENT_NUMBER 1024
#define BUFFER_SIZE 1024
struct fds
{
	int epollfd;
	int sockfd;
};

int setnonblocking(int fd)
{
	int old_option=fcntl(fd, F_GETFL);
	int new_option=old_option|O_NONBLOCK;
	fcntl(fd, F_SETFL, new_option);
	return old_option;
}

void addfd(int epollfd, int fd, bool enable_oneshot)
{
	epoll_event event;
	event.data.fd=fd;
	event.events=EPOLLIN|EPOLLET;
	if(enable_oneshot)
	{
		event.events|=EPOLLONESHOT;
	}
	epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
	setnonblocking(fd);
}

void reset_oneshot(int epollfd, int fd)
{
	epoll_event event;
	event.data.fd=fd;
	event.events=EPOLLONESHOT|EPOLLET|EPOLLIN;
	epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);
}

void* worker(void* arg)
{
	int epollfd=((fds*) arg)->epollfd;
	int sockfd=((fds*) arg)->sockfd;
	printf("start new thread to receive data \n");
	char buf[BUFFER_SIZE];
	memset(buf,'\0', BUFFER_SIZE);
	
	while(1)
	{
		int ret=recv(sockfd, buf, BUFFER_SIZE-1, 0);
		if(ret==0)
		{
			close(sockfd);
			printf("foreiner closed the connection\n");
			break;
		}
		else if(ret<0)
		{
			if(errno == EAGAIN)
			{
				printf("read later\n");
				reset_oneshot(epollfd, sockfd);
				break;
			}
			close(sockfd);
			printf("something wrong \n");
		}
		else
		{
			printf("recv %d data %s\n", ret, buf);
			sleep(5);
		}
	}
	printf("the thread end\n");
}


int main(int argc, char* argv[])
{
	if(argc<=2)
	{
		printf("the parameter are ip and port \n");
		return 1;
	}
	
	const char* ip=argv[1];
	int port=atoi(argv[2]);

	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);

	int listenfd=socket(PF_INET, SOCK_STREAM, 0);
	assert(listenfd>=0);
	
	int ret=bind(listenfd, (const struct sockaddr*)&servaddr, sizeof(servaddr));
	assert(ret!=-1);
	
	ret=listen(listenfd, 5);
	assert(ret!=-1);

	epoll_event events[MAX_EVENT_NUMBER];
	int epollfd=epoll_create(5);
	assert(epollfd!=-1);
    /*listenfd不能注册EPOLLONESHOT事件，否则应用程序只能处理一个客户连接，因为后续客户连接请求将不再触发listenfd上的EPOLLIN事件*/
	addfd(epollfd, listenfd, false);
	
	while(1)
	{
		ret=epoll_wait(epollfd, events, MAX_EVENT_NUMBER, -1);
		if(ret<0)
		{
			printf("something wrong happened \n");
			break;
		}
		else
		{
			for(int i=0; i<MAX_EVENT_NUMBER; ++i)
			{
				int sockfd=events[i].data.fd;
				if(sockfd==listenfd)
				{
					struct sockaddr_in clientaddr;
					socklen_t addrlength=sizeof(clientaddr);
					int connfd=accept(listenfd, (struct sockaddr*) &clientaddr, &addrlength);
					addfd(epollfd, connfd, true);
				}
				else if(sockfd & EPOLLIN)
				{
					pthread_t thread;
					fds fds_for_new_worker;
					fds_for_new_worker.epollfd=epollfd;
					fds_for_new_worker.sockfd=sockfd;
					pthread_create(&thread, NULL, worker, (void*) &fds_for_new_worker);
				}
				else
				{
					printf("something wrong happened \n");
				}
			}
		}
	}
	close(listenfd);
	return 0;
}

```

### 9.4 三组I/O复用函数的比较

![图23](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图23.jpg)

### 9.5 I/O 复用的高级应用一：非阻塞connect

```c++
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/select.h>
#include<arpa/inet.h>
#include<assert.h>

int setnonblocking(int fd)
{
	int old_option=fcntl(fd, F_GETFL);
	int new_option=old_option | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_option);
	return old_option;
}

int unable_connect(const char* ip, int port, int time)
{
	struct sockaddr_in serveraddr;
	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(port);
	inet_pton(AF_INET, ip, &serveraddr.sin_addr);

	int listenfd=socket(PF_INET, SOCK_STREAM, 0);
	int old_option=setnonblocking(listenfd);
	int ret=connect(listenfd, (struct sockaddr*) & serveraddr, sizeof(serveraddr));
	
	if(ret==0)
	{
        /*连接成功，恢复属性，立刻返回*/
		printf("connect success \n");
		fcntl(listenfd, F_SETFL, old_option);
		return listenfd;
	}
	else if(errno !=EINPROGRESS)
	{
        /*只有当errno是EINPROGRESS时才标识连接还在进行，否则出错返回*/
		printf("unblock connect not support\n");
		return -1;
	}
	
	fd_set writefds;
	FD_SET(listenfd, &writefds);
	
	timeval timeout;
	timeout.tv_sec=time;
	timeout.tv_usec=0;
	
	ret=select(listenfd+1, NULL, &writefds, NULL, &timeout);
	
	if(ret<=0)
	{
        /*超时或者连接错误*/
		printf("connection time out \n");
		close(listenfd);
		return -1;
	}
	
	if(!FD_ISSET(listenfd, &writefds))
	{
		printf("no events on socket found\n");
		close(listenfd);
		return -1;
	}
	
	int error=0;
	socklen_t len=sizeof(error);
    /*调用getsockopt来获取并清除sockfd上的错误*/
	if(getsockopt(listenfd, SOL_SOCKET, SO_ERROR, &error, &len)<0)
	{
		printf("get socket option failed \n");
		close(listenfd);
		return -1;
	}
    /*错误号不为0表示连接出错*/
	if(error!=0)
	{
		printf("connection failed after select with the error %d\n", error);
		close(listenfd);
		return -1;
	}
	/*连接成功*/
	printf("connection ready after select with the socket: %d\n", sockfd);
	fcntl(listenfd, F_SETFL, old_option);
	return listenfd;
	
}	
	
int main(int argc, char* argv[])
{
	if(argc<=2)
	{
		printf(" the parameter are ip and port \n");
		return 1;
	}

	const char* ip=argv[1];
	int port=atoi(argv[2]);
	
	int sockfd=unable_connect(ip, port, 10);
	if(sockfd<0)
	{
		return 1;
	}
	
	close(sockfd);	
	return 0;
}
```

### 9.6 I/O复用的高级应用二：聊天室程序

客户端：

```c++
#define _GNU_SOURCE 1
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<errno.h>
#include<assert.h>
#include<poll.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<fcntl.h>

#define BUFFER_SIZE 1024

int main(int argc, char* argv[])
{
	if(argc<=2)
	{
		printf("the parameter are ip and port /n");
		return -1;
	}
	const char* ip=argv[1];
	int port=atoi(argv[2]);
	
	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family=AF_INET;
	addr.sin_port=htons(port);
	inet_pton(AF_INET, ip, &addr.sin_addr);

	int sockfd=socket(PF_INET, SOCK_STREAM, 0);
	assert(sockfd>=0);
	
	if(connect(sockfd, (struct sockaddr*) &addr, sizeof(addr))<0)
	{
		printf("connection failed \n");
		close(sockfd);
		return 1;
	}
	

	pollfd pfd[2];
	pfd[0].fd=0;
	pfd[1].fd=sockfd;
	pfd[0].events=POLLIN;
	pfd[1].events=POLLIN | POLLRDHUP;
	pfd[0].revents=0;
	pfd[1].revents=0;

	char buf[BUFFER_SIZE];
	int pipefd[2];
	int ret=pipe(pipefd);
	assert(ret!=-1);

	while(1)
	{
		ret=poll(pfd, 2, -1);
		if(ret<0)
		{
			printf("poll failed \n");
			break;
		}

		if(pfd[1].revents & POLLRDHUP)
		{
			printf("the server close the connection \n");
			break;
		}
		else if(pfd[1]. revents & POLLIN)
		{
			memset(buf, '\0', BUFFER_SIZE);
			recv(pfd[1].fd, buf, BUFFER_SIZE-1, 0);
			printf("recv data are %s \n", buf);
		}
		
		if(pfd[0].revents & POLLIN)
		{
			ret=splice(0, NULL, pipefd[1], NULL, 32768, SPLICE_F_MOVE | SPLICE_F_MORE);
			ret=splice(pipefd[0], NULL, sockfd, NULL, 32768, SPLICE_F_MOVE | SPLICE_F_MORE);
		}
	}
	
	close(sockfd);
	return 0;
}
```

服务器

```c++
#define _GNU_SOURCE 1    //使用POLLRDHUP事件需要定义_GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<assert.h>
#include<errno.h>
#include<string.h>
#include<fcntl.h>
#include<poll.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#define USER_LIMIT 5
#define FD_LIMIT 65535
#define BUFFER_SIZE 64

struct userdata{
	sockaddr_in address;
	char* writefd;
	char readbuf[BUFFER_SIZE];
};

int setnonblocking(int fd)
{
	int old_option = fcntl(fd,F_GETFL);
	int new_option = old_option | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_option);
	return old_option;
}

int main(int argc, char* argv[])
{
	if(argc<=2)
	{
		printf("the parameter are ip and port \n");
		return 1;
	}
	const char* ip=argv[1];
	int port=atoi(argv[2]);

	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);

	int listenfd=socket(PF_INET, SOCK_STREAM,0);
	assert(listenfd>=0);

	int ret=bind(listenfd, (struct sockaddr*) &servaddr, sizeof(servaddr));
	assert(ret!=1);

	ret=listen(listenfd, 5);
	assert(ret!=-1);

	pollfd fds[USER_LIMIT+1];                          //每个用户都能在fds中有一个，因为刚开始的listenfd会占一个，因此需要USER_LIMIT+1个
	for(int i=1; i<USER_LIMIT+1; i++)
	{
		fds[i].fd=-1;
		fds[i].events=0;
	}
	fds[0].fd=listenfd;                                //fd[0]保存listenfd事件
	fds[0].events=POLLIN | POLLERR;
	fds[0].revents=0;

	struct userdata* users=new userdata[FD_LIMIT];   //用空间换时间，可以直接使用sock进行索引
	int usercount=0;                                   //记录连接用户数量

	while(1)
	{
		int ret=poll(fds, usercount+1, -1);             //poll函数监听,这里不需要全部监听，当用户在线时才需要监听，监听数量是usercount+1
		for (int i = 0; i < USER_LIMIT + 1; ++i)                //循环找产生时间的文件描述符
		{
			if ((fds[i].fd == listenfd) && (fds[i].revents & POLLIN))                   //如果监听的文件描述符上产生事件
			{
				struct sockaddr_in clientaddr;
				socklen_t len = sizeof(clientaddr);
				int connfd = accept(listenfd, (struct sockaddr*)&clientaddr, &len);    //连接
				if (connfd < 0)                         //这里需要对connfd进行一个连接成功判断
				{
					printf("errno is: %d\n", errno);
					continue;
				}
				if (usercount >= USER_LIMIT)         //如果连接人数过多，需要主动断掉连接。
				{
					const char* data = "to many users\n";
					printf("%s\n", data);
					send(connfd, data, strlen(data), 0);
					close(connfd);
					continue;
				}
				usercount++;                                                         //用户数量增加
				users[connfd].address = clientaddr;
				setnonblocking(connfd);
				fds[usercount].fd = connfd;                                            //连接后产生的socket加入监听的队列
				fds[usercount].events = POLLIN | POLLERR | POLLRDHUP;
				fds[usercount].revents = 0;
				printf("comes a new user, now have %d users \n", usercount);
			}
			else if (fds[i].revents & POLLIN)                                         //有数据写入
			{
				memset(users[fds[i].fd].readbuf, '\0', BUFFER_SIZE);
				ret = recv(fds[i].fd, users[fds[i].fd].readbuf, BUFFER_SIZE-1, 0);  //接收数据
				if (ret < 0)                                                      //读数据失败
				{
					if (errno != EAGAIN)          //EAGAIN情况是在ret<0的情况下讨论
					{
						//bzero(&users[fds[i].fd].address, sizeof(users[fds[i].fd].address));
						//memset(users[usercount].readbuf, '\0', BUFFER_SIZE);
						//users[fds[i].fd].writefd = NULL;
						users[fds[i].fd] = users[fds[usercount].fd];
						close(fds[i].fd);
						fds[i] = fds[usercount];                                               //移位补缺
						usercount--;                                                           //用户数量减少
						i--;
					}
				}
                /*测试时，客户端终止连接服务器跳转到此分支而非POLLRDHUP分支*/
				else if (ret == 0)                                                  //暂时无数据
				{
					printf("code should not come to here\n");  //表示对方关闭了连接，已经在EPOLLRDHUP中讨论过
					printf(" a user left\n");
					//users[fds[i].fd] = users[fds[usercount].fd];
					bzero(&users[fds[i].fd].address, sizeof(users[fds[i].fd].address));
					//memset(users[usercount].readbuf, '\0', BUFFER_SIZE);
					//users[fds[i].fd].writefd = NULL;
					close(fds[i].fd);
					if (i != usercount)
					{
						fds[i] = fds[usercount];                                               //移位补缺
						i--;
					}
					usercount--;
					printf("%d\n", usercount);
					continue;
				}
				else                                                               //收到数据，要通知其他用户转发数据                                                             
				{
					for (int j = 1; j < usercount+1; j++)                            //从1开始循环，因为0是listenfd
					{
						if (fds[i].fd==fds[j].fd)                                  //不更改自己的设置
						{
							continue;
						}
						fds[j].events |= ~POLLIN;                                   //其余用户取消EPOLLIN
						fds[j].events |= POLLOUT;                                   //增加EPOLLOUT
						users[fds[j].fd].writefd = users[fds[i].fd].readbuf;
					}
				}
			}
			else if (fds[i].revents & POLLRDHUP)                                            //连接被客户端关闭
			{
				printf(" a user left\n");
				//users[fds[i].fd] = users[fds[usercount].fd];
				bzero(&users[fds[i].fd].address, sizeof(users[fds[i].fd].address));
				//memset(users[usercount].readbuf, '\0', BUFFER_SIZE);
				//users[fds[i].fd].writefd= NULL;
				close(fds[i].fd);
				fds[i] = fds[usercount];                                               //移位补缺
				usercount--;                                                           //用户数量减少
				i--;
			}
			else if (fds[i].revents & POLLOUT)                                         //有代写数据
			{
				if (!users[fds[i].fd].writefd)
				{
					continue;
				}
				ret=send(fds[i].fd, users[fds[i].fd].writefd, strlen(users[fds[i].fd].writefd), 0);
				users[fds[i].fd].writefd = NULL;
				fds[i].events |= ~POLLOUT;
				fds[i].events |= POLLIN;
			}
			else if (fds[i].revents & POLLERR)                   //连接过程出错,使用getsockopt获取错误类型，并且清除错误
			{
				printf("get an error from %d\n", fds[i].fd);
				char errors[100];
				socklen_t len = sizeof(errors);
				memset(errors, '\0', 100);
				if (getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &errors, &len) < 0)
				{
					printf("failed to get socket option \n");
				}
				continue;
			}
		}
		//服务器如何跳出while循环
	}
	delete[] users;
	close(listenfd);
	return 0;
}
```

### 9.7 I/O复用的高级应用三：同时处理TCP和UDP服务

- 服务器如果要同时监听多个端口，就必须创建多个socket，并将它们分别绑定到各个端口上。
- 及时是同一个端口，如果服务器要同时处理该端口上的TCP和UDP请求，则也需要创建两个不同的socket：一个是流的socket，另一个是数据报socket，并将它们都绑定到该端口上。

```c++
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<assert.h>
#include<errno.h>
#include<string.h>
#include<fcntl.h>
#include<sys/epoll.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#define TCP_BUFFER_SIZE 64
#define UDP_BUFFER_SIZE 64
#define EVENT_NUM 1024

int setnonblocking(int fd)
{
	int old_option = fcntl(fd,F_GETFL);
	int new_option = old_option | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_option);
	return old_option;
}

void addfd(int listenfd, int epollfd)
{
	epoll_event event;
	event.data.fd = listenfd;
	event.events = EPOLLIN | EPOLLET;
	setnonblocking(listenfd);
	epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &event);
}

int main(int argc, char* argv[])
{
	if(argc<=2)
	{
		printf("the parameter are ip and port \n");
		return 1;
	}
	const char* ip=argv[1];
	int port=atoi(argv[2]);

	//TCPsocket创建
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);

	int listenfd=socket(PF_INET, SOCK_STREAM,0);
	assert(listenfd>=0);

	int ret=bind(listenfd, (struct sockaddr*) &servaddr, sizeof(servaddr));
	assert(ret!=1);

	ret=listen(listenfd, 5);
	assert(ret!=-1);

	//UDPsocket创建
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);

	int udpfd = socket(PF_INET, SOCK_DGRAM, 0);
	assert(udpfd >= 0);

	ret = bind(udpfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	assert(ret != -1);

	epoll_event events[EVENT_NUM];
	int epollfd = epoll_create(5);
	assert(epollfd != -1);
	addfd(listenfd, epollfd);
	addfd(udpfd, epollfd);

	while (1)
	{
		ret = epoll_wait(epollfd, events, EVENT_NUM, -1);
		char tcp_buf[TCP_BUFFER_SIZE];
		char udp_buf[UDP_BUFFER_SIZE];
		if (ret < 0)
		{
			printf("epoll failure\n");
			break;
		}
		for (int i = 0; i < ret; i++)
		{
			int fd = events[i].data.fd;
			if (fd == listenfd )
			{
				struct sockaddr_in clientaddr;
				socklen_t len = sizeof(clientaddr);
				int connfd = accept(fd, (struct sockaddr*)&clientaddr, &len);
				if (connfd < 0)
				{
					printf("connect failure\n");
					continue;
				}
				addfd(connfd,epollfd);
			}
			else if (fd == udpfd)
			{
				sockaddr_in clientaddr;
				socklen_t len = sizeof(clientaddr);
				memset(udp_buf, '\0', UDP_BUFFER_SIZE - 1);
				ret = recvfrom(udpfd, udp_buf, UDP_BUFFER_SIZE-1, 0, (struct sockaddr*)&clientaddr, &len);
				if (ret <= 0)
				{
					printf("udp recieve error\n");
					break;
				}
				sendto(udpfd, udp_buf, UDP_BUFFER_SIZE - 1, 0, (struct sockaddr*)&clientaddr, len);
			}
			else if (events[i].events & EPOLLIN)
			{
				while (1)
				{
					memset(tcp_buf, '\0', TCP_BUFFER_SIZE - 1);
					ret = recv(fd, tcp_buf, TCP_BUFFER_SIZE-1,0);
					if (ret < 0)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
						{
							break;
						}
						close(fd);
						break;
					}
					else if (ret == 0)
					{
						close(fd);
					}
					else
					{
						send(fd, tcp_buf, ret, 0);
					}
				}
			}
			else
			{
				printf("something wrong happened\n");
			}
		}

	}
	close(listenfd);
	//close(udpfd);
	return 0;
}
```

### 9.8 超级服务xinetd

Linux因特网服务inetd是超级服务。它同时管理着多个自服务，即监听多个端口。现在Linux系统上使用的inetd通常是升级版本xinetd。xinetd程序的原理与inetd相同，但增加了一些控制选项，并提高了安全性。

#### 9.8.1 xinetd配置文件

xinetd采用/etc/xinetd.conf主配置文件和/etc/xinetd.d目录下的子配置文件来管理所有服务。主配置文件包含的是通用选项，这些选项将被所有子配置文件继承。不过子配置文件可以覆盖这些选项。

![图24](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图24.jpg)

#### 9.8.2 xinetd工作流程

![图25](https://github.com/SusanGuo412/Note_HPLSP/raw/main/image/图25.jpg)