#include "stm_info.h"

struct stm_vec
// 用于存储一条条流的向量，包含了扩大等函数。
{
    struct stm_info* data;
    u_int16_t max_size;
    u_int16_t size;
};
void stm_vec_init(struct stm_vec* stmv)
// 初始化 skb_vec
{
    stmv -> max_size = 4;
    stmv -> size = 0;
    stmv -> data = kmalloc(sizeof(stm_info) * stmv -> max_size, GFP_KERNEL)
}
void stm_vec_insert(struct stm_vec* stmv)
// 为 skb_vec 增加一条流。不会初始化新增的流。
{
    if(stmv -> size == stmv -> max_size)    // 如果满了，就扩大
    {
        struct stm_info* temp = stmv -> data;
        stmv -> max_size *= 2;
        stmv -> data = kmalloc(sizeof(stm_info) * stmv -> max_size, GFP_KERNEL)
        memcpy(stmv -> data, temp, sizeof(stm_info) * stmv -> size);
        kfree(temp);
        printk("xmurp-ua: Streams buff expanded to %d.\n", stmv -> max_size);
    }
    stmv -> size++;
}
u_int16_t stm_vec_find(struct stm_vec* stmv, struct sk_buff* skb)
// 根据一个数据包来寻找它属于哪个流。数据包必须是客户端发给服务端的。如果没有找到，返回 0xffff。
{
    int i;
    u_int32_t saddr = ntohl(ip_hdr(skb) -> saddr;
    u_int32_t sport = ntohs(tcp_hdr(skb) -> src);
    for(i = 0; i < stmv -> size; i++)
        if(saddr == stmv -> data[i].saddr && sport == stmv -> data[i].sport)
            return i;
    return 0xffff;
}
void stm_vec_del(struct stm_vec* stmv, u_int16_t pos)
// 删除指定流，后面的往前移。
{
    int i;
    for(i = pos; i < size - 1; i++)
        stmv -> data[i] = stv -> data[i + 1];
    stmv -> size--;
}
