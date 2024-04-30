#import <dlfcn.h>

#import <UIKit/UIKit.h>

 
#import "fishhook.h"
 
static int (*orig_close)(int);
static int (*orig_open)(const char *, int, ...);
 
int my_close(int fd) {
  printf("Calling real close(%d)\n", fd);
  return orig_close(fd);
}
 
int my_open(const char *path, int oflag, ...) {
  va_list ap = {0};
  mode_t mode = 0;
 
  if ((oflag & O_CREAT) != 0) {
    // mode only applies to O_CREAT
    va_start(ap, oflag);
    mode = va_arg(ap, int);
    va_end(ap);
    printf("Calling real open('%s', %d, %d)\n", path, oflag, mode);
    return orig_open(path, oflag, mode);
  } else {
    printf("Calling real open('%s', %d)\n", path, oflag);
    return orig_open(path, oflag, mode);
  }
}
 
#include "util.h"
#include <stdarg.h>
extern "C" void mynslog(char* format, ...)
{
    char str_tmp[BUF_SIZE];
    int i=0;
    va_list vArgList;                            //定义一个va_list型的变量,这个变量是指向参数的指针.
    va_start (vArgList, format);                 //用va_start宏初始化变量,这个宏的第二个参数是第一个可变参数的前一个参数,是一个固定的参数
    i=vsnprintf(str_tmp, BUF_SIZE, format, vArgList); //注意,不要漏掉前面的_
    va_end(vArgList);                            //用va_end宏结束可变参数的获取
    
    string ret;//=gettimehour()+":";
    ret.append(str_tmp,i);
    printf(ret.c_str());
    //NSLog(@"%s",ret.c_str());
   // updatetableview([[NSString alloc]initWithUTF8String:ret.c_str()]);
}
void testthread()
{
    dispatch_queue_t queue = dispatch_queue_create("queueName", DISPATCH_QUEUE_CONCURRENT);
        dispatch_async(queue, ^{
            
            sleep(10);
            rebind_symbols((struct rebinding[2]){{"close", (void*)my_close, (void **)&orig_close}, {"open", (void*)my_open, (void **)&orig_open}}, 2);
            
        });
}


#import <CommonCrypto/CommonCrypto.h>
typedef CCCryptorStatus (*PCCCryptorCreateWithMode)(
    CCOperation     op,                /* kCCEncrypt, kCCDecrypt */
    CCMode            mode,
    CCAlgorithm        alg,
    CCPadding        padding,
    const void         *iv,            /* optional initialization vector */
    const void         *key,            /* raw key material */
    size_t             keyLength,
    const void         *tweak,            /* raw tweak material */
    size_t             tweakLength,
    int                numRounds,        /* 0 == default */
    CCModeOptions     options,
                                                    CCCryptorRef    *cryptorRef);    /* RETURNED */
 
typedef CCCryptorStatus (*PCCCryptorUpdate)(
    CCCryptorRef cryptorRef,
    const void *dataIn,
    size_t dataInLength,
    void *dataOut,              /* data RETURNED here */
    size_t dataOutAvailable,
                                            size_t *dataOutMoved);       /* number of bytes written */

typedef CCCryptorStatus (*PCCCryptorFinal)(
    CCCryptorRef cryptorRef,
    void *dataOut,
    size_t dataOutAvailable,
                                           size_t *dataOutMoved);       /* number of bytes written */

PCCCryptorCreateWithMode orig_CCCryptorCreateWithMode;
PCCCryptorUpdate orig_CCCryptorUpdate;
PCCCryptorFinal orig_CCCryptorFinal;

CCCryptorStatus new_CCCryptorCreateWithMode(
             CCOperation     op,                /* kCCEncrypt, kCCDecrypt */
             CCMode            mode,
             CCAlgorithm        alg,
             CCPadding        padding,
             const void         *iv,            /* optional initialization vector */
             const void         *key,            /* raw key material */
             size_t             keyLength,
             const void         *tweak,            /* raw tweak material */
             size_t             tweakLength,
             int                numRounds,        /* 0 == default */
             CCModeOptions     options,
                                                             CCCryptorRef    *cryptorRef)
{
    NSLog(@"new_CCCryptorCreateWithMode===");
    
    return orig_CCCryptorCreateWithMode(op,mode,alg,padding,iv,key,keyLength,tweak,tweakLength,numRounds,options,cryptorRef);
    
    
    
     
    
}
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
 
 

int main_fish()
{
     
  @autoreleasepool {
       
     
      rebind_symbols((struct rebinding[1]){{"CCCryptorCreateWithMode", (void*)new_CCCryptorCreateWithMode, (void **)&orig_CCCryptorCreateWithMode}}, 1);
      
      int dec;
      string key;
      string data;
      CCCryptorRef cryptor = NULL;
      CCCryptorStatus status = kCCSuccess;
      
      string iv=key;
      CCPadding padding=ccPKCS7Padding;
      CCCryptorCreateWithMode(dec, kCCModeCBC, kCCAlgorithmAES128, padding, iv.c_str(), key.c_str(), key.length(), NULL, 0, 0, kCCModeOptionCTR_BE, &cryptor);
      
      
    rebind_symbols((struct rebinding[2]){{"close", (void*)my_close, (void **)&orig_close}, {"open", (void*)my_open, (void **)&orig_open}}, 2);
 
    // Open our own binary and print out first 4 bytes (which is the same
    // for all Mach-O binaries on a given architecture)
    int fd = open("/var/log/HookHttp/iwechat_short.txt", O_RDONLY);
    uint32_t magic_number = 0;
    read(fd, &magic_number, 4);
    printf("Mach-O Magic Number: %x \n", magic_number);
    close(fd);
 
    //return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
  }
    
    return 1;
}
