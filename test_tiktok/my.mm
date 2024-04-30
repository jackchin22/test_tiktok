//
//  my.cpp
//  test_tiktok
//
//  Created by chenxi on 2024/3/19.
//

#include <stdio.h>

#include <Foundation/Foundation.h>

 
#include <sys/sysctl.h>

#include "util.h"
#include "http.h"

//放前面头文件
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>


pid_t GetParentPidBySvc(){
    NSInteger ppid = 0;
    __asm__ volatile(
                     "mov x16,#39\t\n"
                     "svc 0x80\t\n"
                     "mov %0,x0\t\n"
                     :"=r"(ppid)
                     :
                     :
                     );
    return (pid_t)ppid;
}
//判断是否是调试状态
BOOL isDebugger() {
    int name[4];  //里面放字节码，查询的信息
    name[0] = CTL_KERN;   //内核查询
    name[1] = KERN_PROC;  //查询进程
    name[2] = KERN_PROC_PID;  //传递的参数是进程的id
    name[3] = getpid();   //获取当前进程id
    
    struct kinfo_proc info;  //接收查询结果的结构体
    size_t info_size = sizeof(info);
    
    int error = sysctl(name, 4, &info, &info_size, 0, 0);
    if (error) {
        NSLog(@"查询失败");
        return NO;
    }

     /**
     0000 0000 0000 0000 0100 1000 0000 0100//有调试(info.kp_proc.p_flag=18436)
     &
     0000 0000 0000 0000 0000 1000 0000 0000 （P_TRACED）
     结果：
     0000 0000 0000 0000 0000 1000 0000 0000 （不为0）
     
     
     0000 0000 0000 0000 0100 0000 0000 0100//没有调试(info.kp_proc.p_flag=16388)
     &
     0000 0000 0000 0000 0000 1000 0000 0000   （P_TRACED）
     结果：
     0000 0000 0000 0000 0000 0000 0000 0000 （为0）
     
     结果为0没有调试，结果不为0有调试
     */
    
    pid_t ppid =info.kp_eproc.e_ppid;
    pid_t ppid2=GetParentPidBySvc();
    pid_t ppid3=getppid();
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}



#include <sys/mount.h>

#include <sys/statvfs.h>
int printFreeSpace(const char *path)
{
    struct statvfs st;

    if (statvfs(path, &st) != 0) {
        printf("statvfs error: %s\n", strerror(errno));
        return -1;
    }

    auto freeSize = st.f_bsize * st.f_bfree;
    
    auto v6 = st.f_frsize * st.f_bavail;
    printf("v6:%lu byte, %luGB\n",v6,v6/1024/1024/1024);
    
    printf("current free space of path %s: %lu byte\n, v6:%lu byte", path, freeSize,v6);

    return 0;
}

 

  
#import <dlfcn.h>
typedef int (*my_system) (const char *str);
int call_system(const char *str){
    
    //动态库路径
    char *dylib_path = "/usr/lib/system/libsystem_c.dylib";
    //打开动态库
    void *handle = dlopen(dylib_path, RTLD_GLOBAL | RTLD_NOW);
    if (handle == NULL) {
        //打开动态库出错
        fprintf(stderr, "%s\n", dlerror());
    } else {
        //获取 system 地址
        my_system system = (my_system)dlsym(handle, "system");
        
        //地址获取成功则调用
        if (system) {
            
            int ret = system(str);
            return ret;
        }
        dlclose(handle); //关闭句柄
    }
    
    return -1;
}

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
bool isrunSsh()
{
    int port=22;
    
    string ip="localhost";
    //port=8000;
    
    //ip="118.89.166.53"; //http://118.89.166.53:8000/
    //ip="172.16.14.178";
    //port=9999;
    if(ip.length()==0)
    {
        printf("fail to gethostip");
        return 0;
    }
    
    // 创建TCP套接字
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
   // printf("sockfd = %d\n", sockfd);
    if (-1 == sockfd)
    {
        printf("socket: errno[%d, %s]\n", errno, strerror(errno));
        return 0;
         
    }

    // 将套接字与特定的IP地址和端口号建立连接
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    
    
    //addr.sin_addr.s_addr = INADDR_ANY;
   // addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    
    inet_aton(ip.c_str(), &addr.sin_addr);
    int iConn = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (-1 == iConn)
    {
        printf("connect: errno[%d, %s]\n", errno, strerror(errno));
        close(sockfd);
        return 0;
         
    }
    
    
   
    

   
    // 交互结束，关闭套接字
    close(sockfd);
    
    return 1;
}

void openPort()
{
     
    int server_port=7777;
     
    
   
    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);
    
    //=============
    string ti=gettimename();
    printf("We are the server on port: %d, time:%s\n\n", server_port,ti.c_str());
    
    
    /* Create server socket; will bind with server port and listen */
    int s;
    int optval = 1;
    

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (1) {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server_port);
        addr.sin_addr.s_addr = INADDR_ANY;

         
            
   
        }
                
        //=========

        int bret= ::bind(s, (struct sockaddr*) &addr, sizeof(addr));
        if ( bret< 0)
        {
            perror("Unable to bind");
            exit(EXIT_FAILURE);
        }

        if (listen(s, 1) < 0) {
            perror("Unable to listen");
            exit(EXIT_FAILURE);
        }
     

    
    
    /*
     * Loop to accept clients.
     * Need to implement timeouts on TCP & SSL connect/read functions
     * before we can catch a CTRL-C and kill the server.
     */
    while (1) {
        /* Wait for TCP connection from client */
        int client_skt = accept(s, (struct sockaddr*) &addr,
                                &addr_len);
        if (client_skt < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        
        
       // printf("Client TCP connection accepted\n");
        printf("Client IP：%s PORT：%d\n", inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
        
        
        
        
      
        
        
    }
    
    
    if (s != -1)
        close(s);

    printf("Server exiting...\n");
}


#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include "dyld_cache_format.h"

bool IsRiskModule(uint64_t checkAddress) {
    Dl_info checkDlinfo;
    if(!dladdr((const void *)checkAddress, &checkDlinfo)){
        return false;
    }
    const char * checkfname = checkDlinfo.dli_fname;
    struct mach_header_64 * checkMachHeader  = (struct mach_header_64 *) checkDlinfo.dli_fbase;
    if (checkMachHeader->magic != MH_MAGIC_64)
        return false;
    if(checkMachHeader->ncmds == 0)
        return false;
    struct segment_command_64 * checkCommand  = (struct segment_command_64 *) ((char *)checkMachHeader + sizeof(struct mach_header_64));
    struct segment_command_64 * checkTextCommand  = NULL;
    for (int i =0; i< checkMachHeader->ncmds; i++) {
        if ((checkCommand->cmd == LC_SEGMENT_64)   && (strcmp(checkCommand->segname, "__TEXT") == 0))
        {
            checkTextCommand = checkCommand;
            break;
        }
        checkCommand =(struct segment_command_64 *) ((uint64_t)checkCommand + checkCommand->cmdsize);
    }
    if (!checkTextCommand)
        return false;
    uint64_t checkTextVmSize = checkTextCommand->vmsize;
     
     
    kern_return_t kernReturn = KERN_SUCCESS;
    const char *sharedCachePaths[] = {
        "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64",
        "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
        "/System/Library/dyld/dyld_shared_cache_arm64e",
    };
    int fd = -1;
    for (int i = 0;i < sizeof(sharedCachePaths) / sizeof(char *);i++) {
        fd = open(sharedCachePaths[i], O_RDONLY);
        if (fd != -1) {
            break;
        }
    }
    if (fd == -1)
        return false;
    /*
     *    Globally interesting numbers.
     *    These macros assume vm_page_size is a power-of-2.
     */
   extern    vm_size_t    vm_page_size;
    vm_size_t vmPageSize = vm_page_size;
    unsigned char* p_map =( unsigned char*) mmap(0, vmPageSize, PROT_READ,MAP_NOCACHE|MAP_PRIVATE, fd, 0);
    if (p_map == MAP_FAILED) {
        //映射失败
        close(fd);
        return false;
    }

    struct dyld_cache_header * cacheHeader = ( struct dyld_cache_header *)p_map;
    if(strcmp(cacheHeader->magic, "dyld_v1   arm64") != 0 && strcmp(cacheHeader->magic, "dyld_v1  arm64e") != 0){
        munmap(p_map, vmPageSize);
        close(fd);
        return false;
    }
    struct dyld_cache_mapping_info* mappings = (struct dyld_cache_mapping_info*)(cacheHeader->mappingOffset + (uintptr_t)cacheHeader);
    uintptr_t length =  mappings[0].size;
    munmap(p_map, vmPageSize);
     
    vmPageSize = length;
    p_map =( unsigned char *) mmap(0, vmPageSize, PROT_READ, MAP_NOCACHE|MAP_PRIVATE|MAP_NORESERVE, fd, 0);
    if (p_map == MAP_FAILED) {
        //映射失败
        printf("error:%s\n", strerror(errno));
        close(fd);
        return false;
    }
     
    cacheHeader = ( struct dyld_cache_header *)p_map;
    mappings = (struct dyld_cache_mapping_info*)(cacheHeader->mappingOffset + (uintptr_t)cacheHeader);
    //非越狱系统 imagesCount = 0  越狱系统 imagesCount > 0
    uint32_t imagesCount = cacheHeader->imagesCount;
    if (imagesCount == 0) {
        munmap(p_map, vmPageSize);
        close(fd);
        return false;
    }
     
     
    struct dyld_cache_image_info* dylibs = (struct dyld_cache_image_info*)((uintptr_t)cacheHeader + cacheHeader->imagesOffset);
    struct dyld_cache_image_info * matchDylib = NULL;
    for (uint32_t i=0; i < imagesCount; i++) {
        const char* dylibPath  = (char*)cacheHeader + dylibs[i].pathFileOffset;
        if (strcmp(checkfname, dylibPath) == 0) {
            matchDylib = (struct dyld_cache_image_info*)&dylibs[i];
            //NSLog(@"IsRiskModule 函数,匹配到 filename =%s",dylibPath);
            break;
        }
    }
     
    if (!matchDylib) {
        NSLog(@"IsRiskModule 函数,找不到 filename =%s",checkfname);
        munmap(p_map, vmPageSize);
        close(fd);
        return false;
    }
    uint64_t offset = 0;
    bool bMatch = false;
    for (int i = 0 ; i< cacheHeader->mappingCount; i++) {
        uint64_t StartAddress =mappings[i].address;
        if (matchDylib->address >= StartAddress){
            uint64_t EndAddress = mappings[i].address +mappings[i].size;
            if (matchDylib->address <= EndAddress) {
                offset =  matchDylib->address - mappings[i].address + mappings[i].fileOffset ;
                bMatch = true;
                break;;
            }
        }
    }
    if (!bMatch) {
        munmap(p_map, vmPageSize);
        close(fd);
        return false;
    }
    struct mach_header_64* matchHeader = (struct mach_header_64*)((uintptr_t)cacheHeader + offset);
    if(matchHeader->ncmds == 0)
        return false;
    struct segment_command_64 * matchCommand  = (struct segment_command_64 *) ((char *)matchHeader + sizeof(struct mach_header_64));
    struct segment_command_64 * matchTextCommand  = NULL;
    for (int i =0; i< matchHeader->ncmds; i++) {
        if ((matchCommand->cmd == LC_SEGMENT_64)   && (strcmp(matchCommand->segname, "__TEXT") == 0))
        {
            matchTextCommand = matchCommand;
            break;
        }
     
    matchCommand =(struct segment_command_64 *) ((uint64_t)matchCommand + matchCommand->cmdsize);
    }
    if (!matchTextCommand) {
        munmap(p_map, vmPageSize);
        close(fd);
        return false;
    }
     
    if (matchTextCommand->vmsize != checkTextVmSize ) {
        munmap(p_map, vmPageSize);
        close(fd);
        return true;
    }
    bool bIsRisk = false;
    for (int i = 0; i< checkTextVmSize ; i++) {
        unsigned char Byte1 = *(unsigned char*) ((uint64_t)matchHeader+i);
        unsigned char Byte2 = *(unsigned char*) ((uint64_t)checkMachHeader+i);
        if (Byte1 != Byte2)
        {
            bIsRisk = true;
            NSLog(@"IsRiskModule 被污染的库,filename =%s,基地址 = 0x%llX,函数地址=0x%llX",checkfname,((uint64_t)checkMachHeader),(uint64_t)i);
            break;
        }
    }
    munmap(p_map, vmPageSize);
    close(fd);
    return bIsRisk;
}
 
void printtime(string pbstr)
{
    string structret;
    string str="08 02"+pbstr;
    string pb=stringtodata(str);
     
    parsefrom_numname(pb, 0, structret,"");
    NSLog(@"structret:\n%s",structret.c_str());
    
    string timestr=findstring(structret, "5:  0x(*)\r\n");
    long t=atoxl(timestr.c_str());
    NSDate *nsdate=[NSDate dateWithTimeIntervalSince1970:t/2/1000+8*3600];
    
    long start=(long)([[NSDate date] timeIntervalSince1970]*1000);
    NSDate *nsdateNow=[NSDate dateWithTimeIntervalSince1970:start/1000+8*3600];
   
    NSLog(@"now:%@,nsdate:%@",nsdateNow,nsdate);
    
    
    
    int dd4=4;
}
void testproto()
{
    string structret;
    string pb=stringtodata("08 c4 90 80 82 04 10 02 18 04 22 60 f5 56 6a 87 56 ef 47 f7 41 fd 0a 95 00 59 b9 a8 26 a8 cd 98 e5 94 cf 3c 62 92 37 f7 35 34 27 4b fc f3 6c d7  30 c5 b5 dd 4f f6 6c 68 9d f7 2d 1d cf 3b 32 99 43 e4 bd 44 e8 19 52 ed 1b 77 76 cc 4e f3 24 49 e3 bd e7 e3 62 c4 34 16 0a 53 59 08 e0 c3 07 6d b3 56 2e 0e b8 8b f6 a9 30 57 9a b3 28 92 ce aa f0 cf 63 ");
    NSLog(@"pb:0x%x",pb.length());
    parsefrom_numname(pb, 0, structret,"");
    NSLog(@"struct:\n%s",structret.c_str());
    
    
    printtime("28 d6 b3 84 bc d0 63");
    
    printtime("28 da dc 96 bc d0 63");
     
    
     
    
    int dd4=4;
}
 

 

void testasm()
{
    long long int x = 255;//0xFF
        long long int z = 0;

        asm volatile(
            "ROR %x[z], %x[x], #8\n"
        :[x] "+r"(x),
        [z] "+r"(z)
        :
        : "cc", "memory");
    
    NSLog(@"log addr");
    NSLog(@"log addr22");
     
    
    
    int dd=4;
     
}


 

//参数src：栈帧指针
//参数dst：StackFrameEntry实例指针
//参数numBytes：StackFrameEntry结构体大小
kern_return_t lsl_mach_copyMem(const void * src, const void * dst, const size_t numBytes) {
    vm_size_t bytesCopied = 0;
    //   调用api函数，根据栈帧指针获取该栈帧对应的函数地址
     kern_return_t kret=vm_read_overwrite(mach_task_self(), (vm_address_t)src, (vm_size_t)numBytes, (vm_address_t)dst, &bytesCopied);
    return kret;
}

kern_return_t lsl_mach_copy(const void * src, const void * dst, const size_t numBytes) {
    vm_size_t bytesCopied = 0;
    //   调用api函数，根据栈帧指针获取该栈帧对应的函数地址
     kern_return_t kret=vm_copy(mach_task_self(), (vm_address_t)src, (vm_size_t)numBytes, (vm_address_t)dst);
    return kret;
}

void testvm()
{
    char *a1=(char *)malloc(8);
    char *a2=(char *)malloc(8);
    NSLog(@"adress a1:0x%lx,a2:0x%lx",a1,a2);
    //watchpoint set expression -w write -- 0x283b74ca0
    memcpy(a1, "12345678", 8);
    memcpy(a2, "abcdefgh", 8);
    lsl_mach_copyMem(a1,a2,8);
    NSLog(@"after adress a1:0x%lx,a2:0x%lx",a1,a2);
    
    char *a3=(char *)malloc(8);
    char *a4=(char *)malloc(8);
    memcpy(a4,a1,8);
    lsl_mach_copy(a1,a3,8);
    
    int dd4=4;
    
}

#include "des.h"
#include <objc/runtime.h>
#include <sys/syscall.h>
#include <sys/syscall.h>



 void testf1()
{
     
 }
void testf2()
{
    
}
void *acceptme(void *arg)
{
    pthread_t ptid= pthread_self();
    

   
    
    for(int i=0;i<1000;i++)
    {
        testf1();
        printf("ptid:%lu, i:%d\n",ptid,i);
        sleep(3);
            
    }
    
    return NULL;
}
void test_thread()
{
    int st=time(0);
    pthread_t atid;
    pthread_create(&atid, NULL, acceptme, NULL);
    
     
    
    pthread_t main_tid = pthread_self();
    printf("main_tid:%lu, atid:%lu, atid:0x%lx\n",main_tid,atid,atid);
    
    pthread_t ttid2 = pthread_self();
    int tid=syscall(286);
}

 
void test_thread2()
{
    dispatch_queue_t queue = dispatch_queue_create("com.bootloader.queue.default", DISPATCH_QUEUE_CONCURRENT);
        dispatch_async(queue, ^{
            
            pthread_t ptid= pthread_self();
            

           
            
            for(int i=0;i<1000;i++)
            {
                testf2();
                printf("test_thread2 ptid:%lu, i:%d\n",ptid,i);
                sleep(3);
            }
            
            
        });
}

void t2()
{
    NSLog(@"123");
}
void t1()
{
    t2();
}
void testlr()
{
    t1();
}

 
 
#include <sys/stat.h>

#import <mach-o/dyld.h>
typedef void (*P_dyld_register_func_for_add_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));

static void _rebind_symbols_for_image_my(const struct mach_header *header,
                                      intptr_t slide) {
    NSLog(@"header:0x%lx,slide:0x%lx",header,slide);
}

static void _rebind_symbols_for_image_my2(const struct mach_header *header,
                                      intptr_t slide) {
    NSLog(@"22header:0x%lx,slide:0x%lx",header,slide);
}

void test_addimage()
{
    _dyld_register_func_for_add_image(_rebind_symbols_for_image_my);
    
    _dyld_register_func_for_add_image(_rebind_symbols_for_image_my2);
    
    int dde44=4;
}
extern "C" void testbegin()
{
   
    return testdes();
    
    
    return testlr();
    
    //test_thread();
    return test_thread2();
     
    
    // isDebugger();
    //return;
    //return testvm();
    //vm_read_overwrite
   // return testasm();
     
    
    return testproto();
    bool b=isDebugger();
    return;
    int (*func_stat)(const char *, struct stat *) = stat;
    bool bbr=IsRiskModule((uint64_t)func_stat);
    int ddrr44=4;
    //openPort();
   // return;
    
   // Http h;
    //string body=h.sendurl("http://www.baidu.com/");
    bool bb=isrunSsh();
    NSLog(@"bb:%d",bb);
    
    int ret2=call_system("pause");
    int ret=call_system("ls -al");
    
    //printFreeSpace("/");
    //bool b=isDebugger();
    NSLog(@"testbegin");
    pid_t pid=fork();
    
        
   
    //int ret = kill(pid, 0);
    int dd4=4;
}
