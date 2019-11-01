#include "rkpStream.h"

struct rkpManager
{
    struct rkpStream** data;        // 按照首包的两端口之和的低 8 位放置
};

struct rkpManager* rkpManager_new();                    // 构造函数
void rkpManager_del(struct rkpManager*);                // 析构函数

u_int8_t rkpManager_execute(struct rkpManager*, struct sk_buff*);           // 处理一个数据包。返回值：0，出错，1，accept，2，stolen，3，drop
void rkpManager_refresh(struct rkpManager*);                              // 清理过时的流

struct rkpStream* __rkpManager_find(struct rkpManager*, struct sk_buff*);   // 寻找一个数据包属于哪个流
void __rkpManager_stream_add(struct rkpManager*, struct sk_buff*);          // 增加一个流
