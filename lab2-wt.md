### 代码结构

| 文件 | 职责 |
| --- | --- |
| `src/device.{h,cpp}` | 设备与 IPv4 地址发现、pcap handle、帧注入、接收循环与 tick |
| `src/packetio.{h,cpp}` | Ethernet II 封装、最小帧填充和接收回调 |
| `src/ip.{h,cpp}` | PT3 的 `sendIPPacket()`、`setIPPacketReceiveCallback()`、`setRoutingTable()`；IPv4 首部校验、本地交付和转发 |
| `src/arp.{h,cpp}` | 下一跳 MAC 解析、缓存、等待队列和重试 |
| `src/routing.{h,cpp}` | connected/static/dynamic 路由及最长前缀匹配 |
| `src/link_state.{h,cpp}` | HELLO、LSA 泛洪与老化、Dijkstra、动态路由安装 |
| `src/netstack.{h,cpp}` | 初始化、按 EtherType 分发报文、驱动协议定时器 |
| `src/utils.h` | 长度常量、字节序读写和日志工具 |
| `src/lab2_demo.cpp` | CP3–CP6 演示命令与 ICMP Echo |
| `src/evaluate/` | 四个检查点的建网脚本、隔离运行入口和抓包程序 |

发送路径：`sendIPPacket()` 构造 IPv4 首部并查路由，经 ARP 解析下一跳（静态 MAC 路由直接发送），再由 `sendFrame()` 封装以太网帧、`injectFrame()` 注入设备。接收路径：pcap → Ethernet 分发 → IP/ARP/链路状态模块。IP 包目的地址为本地任一接口时交付上层回调，否则递减 TTL、更新校验和并重新查路由转发。

所有协议状态由单线程事件循环管理。报文缓冲区是每次调用独有的局部对象，ARP 等待队列保存副本；接收回调内可以再次调用发送接口。回调收到的缓冲区仅在本次调用期间有效。本实现不支持跨线程并发调用或嵌套接收循环。

### Writing Task 2

(1) ARP Reply 的 Target MAC 字段与 ARP Request 的 Sender MAC 字段相同。

(2) 用 `ip.flags.df == 0` 过滤，共 $6$ 个 IPv4 包。

(3) IPv4 为 $20$ 字节。IPv6 基本首部固定为 $40$ 字节，另有 $18$ 个 IPv6 包带 $8$ 字节 Hop-by-Hop Options 扩展首部，完整首部链为 $48$ 字节。

### Writing Task 3

`sendIPPacket()` 的调用者提供源 IP、目的 IP、协议号和负载，不提供 MAC。发送时先做最长前缀匹配：

- connected 路由：目的 IP 位于出接口的直连子网，下一跳 IP 就是目的 IP。
- dynamic 路由：链路状态计算给出首跳邻居在出接口上的 IP。
- static 路由：`setRoutingTable()` 已接收调用者指定的下一跳 MAC，直接使用。

前两种情况交给 ARP。缓存以（设备，下一跳 IP）为键，未过期则直接发送；未命中则广播 ARP Request，并复制 IP 包到该下一跳的等待队列。收到指向本接口的 ARP Request 或目标 MAC 为本机的 ARP Reply 后更新映射、按入队顺序发送等待包；对本接口的请求还会发送 Reply。

### Writing Task 4

采用链路状态路由，自定义控制报文使用 EtherType `0x88b6`，直接通过以太网广播，不依赖尚未建立的 IP 路由或 ARP。

1. Router ID 为本机最高 IPv4 地址。每个接口每 $1$ s 广播 HELLO，携带 Router ID 与本接口 IP；$3$ s 未收到某邻居的 HELLO 则删除该邻居。
2. 每个路由器生成 LSA，宣告当前存活邻居及链路 cost、本机直连前缀及前缀 metric（为 $0$）。默认链路 cost 为 $1$；`linkStateSetLinkCost()` 可以设置正权值。
3. LSA 带 $64$ 位序号，初值来自单调时钟，之后每次生成递增。只接收更大序号，并向入接口以外的接口泛洪；收到自身或旧序号的 LSA 直接丢弃。序号机制终止环形拓扑中的重复泛洪。本地 LSA 每 $5$ s 刷新，远端 LSA $15$ s 未更新则老化。
4. 拓扑变化后，以本机 Router ID 为源在 LSDB 描述的图上运行 Dijkstra，记录最短距离和首跳邻居。一个前缀的候选度量为“到宣告路由器的距离 + 前缀 metric”；多个路由器宣告同一前缀时选最小度量，同度量按首跳 Router ID 决胜。
5. 根据首跳邻居得到出接口与下一跳 IP，整体替换 dynamic 路由，保留 connected/static 路由。多个控制报文在同一轮收到时，只在该轮 tick 中重算一次。

路由查找先比较前缀长度，相同长度时 connected 优先于 static，static 优先于 dynamic。每个（前缀，来源类型）只保存一条路由，dynamic 的最佳候选已由链路状态模块选好。远端宣告的本地直连前缀可以留在 dynamic 表中，由上述来源优先级决定使用 connected；更长的 static/dynamic 前缀仍优先于较短的 connected 前缀。

### Corner Cases

- **断链及收敛期间的旧信息**：CP4、CP5 会触发设备发送失败和 pcap 描述符错误，接收循环仍继续运行，并避免错误描述符造成忙循环。HELLO 超时后重建本地 LSA、重新计算路由；失去可达路径的旧 LSA 不再产生路由。转发仍检查 TTL，防止收敛中的暂时环路无限转发。
- **环形拓扑和等价路径**：CP5 存在环和等长路径。LSA 序号抑制重复、乱序报文；Dijkstra 按（距离，Router ID）取堆顶，只保留一条确定的最短路径；同一前缀的多个来源按 WT4 选择。
- **控制报文丢失和 ARP 无应答**：周期性 HELLO/LSA 与超时处理允许丢包后恢复；ARP 使用有界等待队列和有限重试。已排队的 IP 包保留当时的出接口与下一跳，路由重算不重新选路；它可能按旧决定发送，也可能随 ARP 超时丢弃。
- **调用与缓冲区边界**：公共发送接口检查参数及 MTU；接收入口检查报文长度。IP 首部已由 IP 层验证后，转发函数和演示程序不再重复验证。

### 实验

环境：WSL2 Linux 5.15.167.4、GCC 11.4.0、CMake 3.22.1、libpcap 1.10.7。注意 veth MAC、进程标识和 LSA 初始序号由运行环境生成，复现时数值可以不同。

编译与实验运行：

```bash
cmake -S . -B build
cmake --build build -j4
mkdir -p evidence
bash src/evaluate/run.sh cp3 evidence/cp3
bash src/evaluate/run.sh cp4 evidence/cp4
bash src/evaluate/run.sh cp5 evidence/cp5
bash src/evaluate/run.sh cp6 evidence/cp6
```

`run.sh` 创建隔离的 user/mount/network namespace，并在其中建立各节点。每个节点设置 iptables 的 INPUT/OUTPUT/FORWARD 丢弃规则，关闭内核 ARP 应答（`net.ipv4.conf.all.arp_ignore=8`），因此 IP 转发、Echo Reply 和 ARP Reply 均来自用户态实现。脚本结束后删除本次网络命名空间；宿主机规则不变。抓包器使用 AF_PACKET 记录标准 pcap，再由 tcpdump 解码；运行时长使用单调时钟，报文时间戳使用系统时间。

演示程序支持 `ping IP [COUNT]`、`distances`、`lookup IP`、`setroute DEST MASK MAC DEV` 和 `quit`，其中 ICMP Echo 实现自演示程序。四个 CP 的终端证据分别为 `checkpoints/cp3.txt` 至 `cp6.txt`。

实验结果见 `checkpoints/` 内文档，其本身应该是易读的，此处不再详细解释。
