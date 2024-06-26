//
//  ViewController.m
//  test_tiktok
//
//  Created by chenxi on 2024/3/19.
//

#import "ViewController.h"
#import <test_tiktok-Swift.h>
#import <Foundation/Foundation.h>
#include <pthread/pthread.h>

@interface ViewController ()

@end

@implementation ViewController


void testbegin();

NSString* stringFromDict(NSDictionary *dictionary)
{
    //NSDictionary *dictionary = @{@"key1": @"value1", @"key2": @"value2"};
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dictionary options:kNilOptions error:&error];
    NSString *jsonString = @"";
    if (!error) {
        jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    NSLog(@"转换后的字符串：%@", jsonString);
    
    return jsonString;
}

NSString* stringFromDict2(NSDictionary *dictionary)
{
    //NSDictionary *dictionary = @{@"key1": @"value1", @"key2": @"value2"};
    NSError *error;
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:dictionary format:NSPropertyListXMLFormat_v1_0 options:kNilOptions error:&error];
    NSString *plistString = @"";
    if (!error) {
        plistString = [[NSString alloc] initWithData:plistData encoding:NSUTF8StringEncoding];
    }
    NSLog(@"转换后的字符串2：%@", plistString);
    NSArray *nsarray=[plistString componentsSeparatedByString:@"\n"];
    
    for(NSString *str in nsarray)
    {
        NSLog(@"%@",str);
    }
    
    return plistString;
}

NSString* stringFromDict3(NSDictionary *dictionary)
{
    for (NSString *key in dictionary) {

               NSLog(@"%@ = %@",key,[dictionary objectForKey:key]);

           }
    
    return @"";
}



//keychain
/** 增/改 */
- (void)insertAndUpdate:(id)sender {
    
    /**
     说明：当添加的时候我们一般需要判断一下当前钥匙串里面是否已经存在我们要添加的钥匙。如果已经存在我们就更新好了，不存在再添加，所以这两个操作一般写成一个函数搞定吧。
     
     过程关键：1.检查是否已经存在 构建的查询用的操作字典：kSecAttrService，kSecAttrAccount，kSecClass（标明存储的数据是什么类型，值为kSecClassGenericPassword 就代表一般的密码）
     
     　　　2.添加用的操作字典：　kSecAttrService，kSecAttrAccount，kSecClass，kSecValueData
     
     　　　3.更新用的操作字典1（用于定位需要更改的钥匙）：kSecAttrService，kSecAttrAccount，kSecClass
     
     　　　　　　　　操作字典2（新信息）kSecAttrService，kSecAttrAccount，kSecClass ,kSecValueData
     */
    
    NSLog(@"插入 : %d",  [self addItemWithService:@"com.tencent" account:@"李雷" password:@"911"]);
}
 
-(BOOL)addItemWithService:(NSString *)service account:(NSString *)account password:(NSString *)password{
    
    //先查查是否已经存在
    //构造一个操作字典用于查询
    
    NSMutableDictionary *queryDic = [NSMutableDictionary dictionary];
    
    [queryDic setObject:service forKey:(__bridge id)kSecAttrService];                         //标签service
    [queryDic setObject:account forKey:(__bridge id)kSecAttrAccount];                         //标签account
    [queryDic setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];//表明存储的是一个密码
    
    OSStatus status = -1;
    CFTypeRef result = NULL;
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)queryDic, &result);
    
    if (status == errSecItemNotFound) {                                              //没有找到则添加
        
        NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];    //把password 转换为 NSData
        
        [queryDic setObject:passwordData forKey:(__bridge id)kSecValueData];       //添加密码
        
        status = SecItemAdd((__bridge CFDictionaryRef)queryDic, NULL);             //!!!!!关键的添加API
        
    }else if (status == errSecSuccess){                                              //成功找到，说明钥匙已经存在则进行更新
        
        NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];    //把password 转换为 NSData
        
        NSMutableDictionary *dict = [[NSMutableDictionary alloc] initWithDictionary:queryDic];
        
        [dict setObject:passwordData forKey:(__bridge id)kSecValueData];             //添加密码
        
        status = SecItemUpdate((__bridge CFDictionaryRef)queryDic, (__bridge CFDictionaryRef)dict);//!!!!关键的更新API
        
    }
    
    return (status == errSecSuccess);
}
 
 
/** 查 */
- (void)select:(id)sender {
    
    /**
     过程：
     1.(关键)先配置一个操作字典内容有:
     kSecAttrService(属性),kSecAttrAccount(属性) 这些属性or标签是查找的依据
     kSecReturnData(值为@YES 表明返回类型为data),kSecClass(值为kSecClassGenericPassword 表示重要数据为“一般密码”类型) 这些限制条件是返回结果类型的依据
     
     2.然后用查找的API 得到查找状态和返回数据（密码）
     
     3.最后如果状态成功那么将数据（密码）转换成string 返回
     */
    
    NSLog(@"%@", [self passwordForService:@"com.tencent" account:@"李雷"]);
    
}


 
//用原生的API 实现查询密码
- (NSString *)passwordForService:(nonnull NSString *)service account:(nonnull NSString *)account{
    
    //生成一个查询用的 可变字典
    NSMutableDictionary *queryDic = [NSMutableDictionary dictionary];
    
    //首先添加获取密码所需的搜索键和类属性：
    [queryDic setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass]; //表明为一般密码可能是证书或者其他东西
    [queryDic setObject:(__bridge id)kCFBooleanTrue  forKey:(__bridge id)kSecReturnData];     //返回Data
    
    [queryDic setObject:service forKey:(__bridge id)kSecAttrService];    //输入service
    [queryDic setObject:account forKey:(__bridge id)kSecAttrAccount];  //输入account
    
   
     
    //查询
    OSStatus status = -1;
    CFTypeRef result = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)queryDic,&result);//核心API 查找是否匹配 和返回密码！
    if (status != errSecSuccess) { //判断状态
 
        return nil;
    }
    NSLog(@"result:%@",result);
    CFShow(result);
    
    
    //返回数据
//    NSString *password = [[NSString alloc] initWithData:(__bridge_transfer NSData *)result encoding:NSUTF8StringEncoding];//转换成string
    
    //删除kSecReturnData键; 我们不需要它了：
    [queryDic removeObjectForKey:(__bridge id)kSecReturnData];
    //将密码转换为NSString并将其添加到返回字典：
    NSString *password = [[NSString alloc] initWithBytes:[(__bridge_transfer NSData *)result bytes] length:[(__bridge NSData *)result length] encoding:NSUTF8StringEncoding];
    
    [queryDic setObject:password forKey:(__bridge id)kSecValueData];
    
    NSLog(@"查询 : %@", queryDic);
    
    
    return password;
}
 
 
/** 删 */
- (IBAction)delete:(id)sender {
    
    NSLog(@"删除 : %d", [self deleteItemWithService:@"com.tencent" account:@"李雷"]);
}
 
 
-(BOOL)deleteItemWithService:(NSString *)service account:(NSString *)account{
    
    NSMutableDictionary *queryDic = [NSMutableDictionary dictionary];
    
    [queryDic setObject:service forKey:(__bridge id)kSecAttrService];                         //标签service
    [queryDic setObject:account forKey:(__bridge id)kSecAttrAccount];                         //标签account
    [queryDic setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];//表明存储的是一个密码
    
    
    OSStatus status = SecItemDelete((CFDictionaryRef)queryDic);
    
    return (status == errSecSuccess);
}


- (void)run {
    NSLog(@"%@",[NSThread currentThread]);
}

- (void)operation_thread {
    NSBlockOperation *operation = [NSBlockOperation blockOperationWithBlock:^{
        //子线程执行
        NSLog(@"%@",[NSThread currentThread]);
        NSLog(@"%@",[NSThread currentThread]);
        NSLog(@"%@",[NSThread currentThread]);
    }];
    [operation setCompletionBlock:^{
        //任务完成调用的方法
        NSLog(@"completion %@",[NSThread currentThread]);
    }];
    NSOperationQueue *queue = [[NSOperationQueue alloc] init];
    //[queue addOperation:operation];
    
    
        [queue addOperationWithBlock:^{
            NSLog(@"3 %@",[NSThread currentThread]);
            NSLog(@"3 %@",[NSThread currentThread]);
            NSLog(@"3 %@",[NSThread currentThread]);
        }];
    
}

- (void)test10 {
    // 创建observer
    CFRunLoopObserverRef observer = CFRunLoopObserverCreate(kCFAllocatorDefault, kCFRunLoopBeforeWaiting | kCFRunLoopAfterWaiting, YES, 0, observeRunLoopActivities, NULL);
    // 添加observer到Runloop中
    CFRunLoopAddObserver(CFRunLoopGetMain(), observer, kCFRunLoopCommonModes);
    // 释放
    CFRelease(observer);
}

- (void)test11 { //CFRunLoopObserver使用
    // 创建observer
    NSString *nsstr=[NSString stringWithUTF8String:"nsTTKNSLogInitTask"];
    char *cstr="TTKNSLogInitTask";
    char *cstr2="2TTKNSLogInitTask";
    CFRunLoopObserverRef observer = CFRunLoopObserverCreateWithHandler(kCFAllocatorDefault, kCFRunLoopBeforeWaiting | kCFRunLoopAfterWaiting, YES, 0, ^(CFRunLoopObserverRef observer, CFRunLoopActivity activity) {
        
        int dd4=4;
        NSLog(@"nsstr:%s",cstr);
        NSLog(@"nsstr:%s",cstr2);
        NSLog(@"nsstr:%@",nsstr);
        switch (activity) {
            case kCFRunLoopEntry:
                NSLog(@"block--kCFRunLoopEntry");
                break;
            case kCFRunLoopBeforeTimers:
                NSLog(@"block--kCFRunLoopBeforeTimers");
                break;
            case kCFRunLoopBeforeSources:
                NSLog(@"block--kCFRunLoopBeforeSources");
                break;
            case kCFRunLoopBeforeWaiting:
                NSLog(@"block--kCFRunLoopBeforeWaiting");
                break;
            case kCFRunLoopAfterWaiting:
                NSLog(@"block--CFRunLoopAfterWaiting");
                break;
            case kCFRunLoopExit:
                NSLog(@"block--kCFRunLoopExit");
                break;
            default:
                NSLog(@"block--default");
                break;
        }
    });
    // 添加observer到Runloop中
    CFRunLoopAddObserver(CFRunLoopGetMain(), observer, kCFRunLoopCommonModes);
    // 释放
    CFRelease(observer);
}
 

void observeRunLoopActivities(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info) {
    switch (activity) {
        case kCFRunLoopEntry:
            NSLog(@"kCFRunLoopEntry");
            break;
        case kCFRunLoopBeforeTimers:
            NSLog(@"kCFRunLoopBeforeTimers");
            break;
        case kCFRunLoopBeforeSources:
            NSLog(@"kCFRunLoopBeforeSources");
            break;
        case kCFRunLoopBeforeWaiting:
            NSLog(@"kCFRunLoopBeforeWaiting");
            break;
        case kCFRunLoopAfterWaiting:
            NSLog(@"kCFRunLoopAfterWaiting");
            break;
        case kCFRunLoopExit:
            NSLog(@"kCFRunLoopExit");
            break;
        default:
            NSLog(@"default");
            break;
    }
}
 
- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    NSLog(@"begin...");
    
    //[self test11]; //CFRunLoopObserver使用
    //return;
    
            //[self _mianQueueDeadLock];
            //[self _serialQueueDeadLock];
    
    
   // [self operation_thread];
    
    NSLog(@"begin2...");
    
    Person *p=[[Person alloc]init];
    
    //[p test];
    
    UILabel *label = [[ UILabel alloc] init];
    p.name=@"hello123";
        label.text = [p name];
        label.frame = CGRectMake(50,50,100,100) ;
        label.backgroundColor = [UIColor redColor];
        [self.view addSubview:label];
    
    
    NSLog(@"end...");
    
    [Person test1 ];
    BOOL b=[JailBreakDetection isJailBroken];
    
     
    
    NSLog(@"end1...");
    
    testbegin();
    
    NSDictionary *dictionary = @{@"key1": @"value1", @"key2": @"value2"};
    NSMutableDictionary *dict=[NSMutableDictionary dictionary];
    [dict setObject:@"value1" forKey:@"key1"];
    
    char *str="12345";
    NSData *data=[NSMutableData dataWithBytes:str length:5];
    [dict setObject:data forKey:@"key2"];
    NSString *dictstr=stringFromDict3(dict);
   
    //[self insertAndUpdate:self];
    [self select:self];
    
}

 

#pragma mark - Private

- (void)_mianQueueDeadLock {
    dispatch_sync(dispatch_get_main_queue(), ^(void){
        NSLog(@"这里死锁了");
    });
}

- (void)_serialQueueDeadLock {
    dispatch_queue_t queue1 = dispatch_queue_create("1serialQueue", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_t queue2 = dispatch_queue_create("2serialQueue", DISPATCH_QUEUE_SERIAL);
    
    dispatch_sync(queue1, ^{
        NSLog(@"11111");
        printf("(2)：%lu",  pthread_self());
        
        dispatch_sync(queue2, ^{
            // 如果使用queue2就不会发生死锁，使用queue1就会死锁
            NSLog(@"22222");
        });
    });
    
    NSLog(@"123");
}

@end
