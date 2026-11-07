# Lab 3 报告

### 代码结构

| 文件 | 职责 |
| --- | --- |
| `src/device.{h,cpp}` | 设备与 IPv4 地址发现、pcap handle、帧注入、单步轮询与接收循环、捕获统计 |
| `src/packetio.{h,cpp}` | Ethernet II 封装、最小帧填充、接收回调、可复现的 TCP 丢包注入 |
| `src/ip.{h,cpp}` | PT3 的 `sendIPPacket()`、`setIPPacketReceiveCallback()`、`setRoutingTable()`；IPv4 首部校验、转发、分片发送与重组分发 |
| `src/ipfrag.{h,cpp}` | `IpReassembler`：按（源、目的、标识、协议）重组 IPv4 分片 |
| `src/routing.{h,cpp}` | connected/static/dynamic 路由与最长前缀匹配 |
| `src/arp.{h,cpp}` | 下一跳 MAC 解析、缓存、等待队列、`arpLookup()` |
| `src/link_state.{h,cpp}` | HELLO、LSA 泛洪与老化、Dijkstra、动态路由安装 |
| `src/egress.{h,cpp}` | 路由器出接口的令牌桶整形、FIFO 与加权公平队列（DRR） |
| `src/tcp.{h,cpp}` | PT4 的 TCP 状态机、重传、流量控制、Reno/BBR 拥塞控制 |
| `src/socket.{h,cpp}` | `__wrap_*` POSIX 接口、fd 表、`getaddrinfo`、进程退出关闭 |
| `src/netstack.{h,cpp}` | 协议栈初始化、按 EtherType 分发报文、驱动所有定时器 |
| `src/lab3_router.cpp` | 只转发并驱动定时器的四节点实验路由器 |
| `src/http_proxy.cpp` | CL8 的 HTTP 代理：浏览器侧真实 socket，源站侧用户态 TCP |
| `src/evaluate/tcp_tool.cpp` | 评估应用：source/sink/echo/同时打开关闭 |
| `src/evaluate/ip_tool.cpp` | 评估应用：分片收发、原始 IP 流收发 |
| `src/evaluate/http_origin.cpp` | 运行在自建 TCP 上的固定页面 HTTP 源站 |
| `src/evaluate/unit_tests.cpp` | CL9 的 21 个单元测试 |
| `src/evaluate/*.py`、`*.sh` | 检查点与 Challenge 的建网、抓包、分析和覆盖率脚本 |

发送路径：应用调用 `socket()` 等接口后，`socket.cpp` 把数据交给 `tcp.cpp` 构造 TCP 段，`sendIPPacket()` 构造 IPv4 首部并查路由；静态路由直接取 MAC，connected/dynamic 路由交给 ARP；`sendFrame()` 封装 Ethernet II 帧后由 `injectFrame()` 注入设备。路由器转发时可选经过 `egress.cpp` 的整形/调度队列。接收路径：pcap → `packetio` → EtherType 分发 → IP（必要时重组）/ARP/链路状态 → TCP 接收缓冲；阻塞中的 socket 调用通过 `netstackPump()` 驱动同一套接收与定时器代码。

所有协议状态由单线程事件循环管理。阻塞的 `connect/accept/read/write` 在等待条件满足时泵送协议栈，服务端与客户端各自在自己的进程中推进。报文缓冲区是调用期内的局部对象；TCP/ARP/分片模块保存必要的副本。公共接口不做跨线程同步，也不支持嵌套接收循环。

### TCP 设计

**状态与序号。** 实现 RFC 793 的 CLOSED、LISTEN、SYN_SENT、SYN_RECEIVED、ESTABLISHED、FIN_WAIT_1、FIN_WAIT_2、CLOSING、TIME_WAIT、CLOSE_WAIT、LAST_ACK。初始序号由单调时钟、进程号与线性同余计数器生成；SYN 与 FIN 各消耗一个序号。序号比较统一使用模 $2^{32}$ 的有符号差，避免回绕错误。报文校验和按 IPv4 伪首部加 TCP 段计算，接收时校验零值。

**握手与关闭。** 主动打开发送 SYN，被动打开由监听 TCB 派生连接 TCB 并回 SYN-ACK。SYN_SENT 收到不带 ACK 的 SYN 时进入 SYN_RECEIVED 并回 SYN-ACK，这是同时打开路径；FIN_WAIT_1 收到对端 FIN 时进入 CLOSING，收到自己 FIN 的 ACK 后进入 TIME_WAIT，这是同时关闭路径。TIME_WAIT 保持 $8$ s 后释放。监听 socket 的已完成连接进入 accept 队列，队列长度受 backlog 限制。

**重传。** 每个连接维护 SRTT、RTTVAR 与 RTO，初值 $1$ s，按 RFC 6298 的加权平均更新，限制在 $200$ ms 到 $3$ s；超时按指数退避到 $6$ s，最多重试 $8$ 次。超时重传从 `sndUna` 起按接收窗口重发已发送的数据（Go-Back-N 语义），FIN 也参与重传。收到 $3$ 个真正的重复 ACK 时快速重传，并进入快速恢复。纯窗口更新 ACK 不计入重复 ACK（按 RFC 793 的 SND.WL1/SND.WL2 思想，只在窗口字段未变化时计数）。

**流量控制。** 接收缓冲上限 $65535$ 字节，每发送一个 ACK 都填入当前可接收窗口；应用读取后若窗口增长至少一个 MSS（或原先为零）就发送窗口更新。发送端用 `min(对端窗口, cwnd)` 限制在途数据，窗口为零时按 RTO 发送单字节零窗口探测。发送缓冲上限 $256$ KiB，使官方 perf 程序的 146 KB 写不必等待接收端逐段读取。

**拥塞控制。** 默认 Reno：慢启动、拥塞避免、三次重复 ACK 快速重传与快速恢复；超时把 `ssthresh` 设为在途量的一半并把 `cwnd` 降为 1 MSS。设置 `NETSTACK_CC=bbr` 时使用 BBR：估计送达速率与最小 RTT，按 Startup → Drain → ProbeBW → ProbeRTT 切换，`cwnd = cwnd_gain × BtlBw × RTprop`，并用令牌桶按 `pacing_gain × BtlBw` 发送。BBR 是面向本实验的简化实现，没有内核版的完整带宽过滤器和长期探测状态，但保留了带宽/RTT 估计、增益循环与起搏的基本行为。

**选项与窗口扩大。** SYN 携带 MSS 选项，解析对端 MSS；不使用 SACK、时间戳或窗口扩大。由于本实现的接收窗口不超过 $65535$，不发送窗口扩大选项，同时按 RFC 7323 不放大对端窗口字段。

### POSIX 接口

`__wrap_socket()` 只接受 `AF_INET`、`SOCK_STREAM` 与协议 0/TCP；返回从 $10000$ 开始的假 fd，避免与系统 fd 冲突。`bind()` 检查地址属于本机接口；`listen()` 允许未绑定的 socket 自动分配临时端口；`connect()` 在路由尚未收敛（`ENETUNREACH`）时泵送并重试最多 $5$ s；`accept()` 在没有完成连接时泵送等待。`read/write` 对非本栈 fd 原样转交 `__real_read/__real_write`，`close` 同理。`write` 在发送缓冲满时泵送等待；`read` 在无数据时泵送等待，收到 FIN 且缓冲为空时返回 0。

`close()` 在拆除 TCB 前最多泵送 $5$ s，让排队数据有机会上线；进程正常退出时 `atexit` 关闭所有栈内 socket，使依赖进程终止关闭 fd 的程序（例如官方 perf_client）也能发出 FIN。`send/recv/sendto/recvfrom` 作为 `write/read` 的包装；`recv` 支持 `MSG_DONTWAIT`。

`getaddrinfo` 仅覆盖手册要求的范围：`node` 为数字 IPv4 或 NULL，`service` 为十进制端口或 NULL，`hints` 为 NULL 或 `AF_INET`、`SOCK_STREAM`、协议 0/TCP、`ai_flags == 0`。手册中 `hints->ai_socktype == IPPROTO_TCP` 与 POSIX 的 `SOCK_STREAM` 冲突，本实现按 POSIX 解释该字段。

### IPv4 分片与重组

`sendIPPacket()` 的负载超过一个以太网帧可容纳的 1480 字节时，按 1480 字节（8 的倍数）分片，所有分片共用同一个 IP 标识；除最后一片外置 MF，偏移按 8 字节为单位填写，首部校验和逐片计算。目的主机把分片交给 `IpReassembler`：以（源地址、目的地址、标识、协议）为键，最多保存 8 个未完成数据报，每项预留 65515 字节负载空间；按字节记录已到达位置，收到最后一片后确定总长，缺口补齐后重建首部（清除 MF/偏移、重算总长与首部校验和）并交给上层回调。30 s 未完成的分片被老化删除。路由器对非本地的分片逐片转发，不做重组。

### 路由器加权公平队列

`egress.cpp` 通过环境变量配置一个出接口的令牌桶速率、队列上限和工作模式。FIFO 模式用于制造拥塞瓶颈；`wfq` 模式为每个源 IP 维护独立队列，队列上限按流计算，调度使用差额轮询（DRR）：每轮给非空流增加 `1500 × weight` 字节的信用，按持久化的轮转指针依次发送，信用耗尽或令牌不足时停在当前流，待令牌恢复后继续，从而保证长期服务量与权重成正比。该实现同时支持 CL3 的权重比和 CL5/CL6/CL7 的 FIFO 瓶颈。

### Writing Task 5

(1) `trace.pcap` 中共有 $2$ 个 TCP 会话：一个端口 $43120$ 的短会话包含 $12$ 个 TCP 段，另一个端口 $43122$ 的长会话包含 $1652$ 个 TCP 段。

(2) 两个会话的四元组（按客户端到服务器方向书写）为

- $\langle 10.0.0.74, 43120, 115.27.207.221, 80 \rangle$；
- $\langle 10.0.0.74, 43122, 115.27.207.221, 80 \rangle$。

(3) 第 $86$ 号包的 TCP 首部窗口字段为 `0x0055`，即 $85$。该连接在 SYN 与 SYN-ACK 中都携带了窗口扩大选项，移位量为 $9$（选项 `01 03 03 09` 中的 `09`）。握手完成后，接收窗口按移位量放大，因此实际接收窗口为

$$85 \times 2^9 = 85 \times 512 = 43520\ \text{字节}.$$

SYN 段本身的窗口字段不放大；窗口扩大只作用于握手之后的段。该值反映发送该 ACK 时接收端缓冲区还能接收的字节数。

### Writing Task 6

**评估方法与使用方式。** 评估环境由 `src/evaluate/run.sh` 与 `src/evaluate/lab3lib.sh` 初始化（PT5）：脚本在私有的 user/mount/network namespace 中挂载 tmpfs 到 `/run`，建立 netns 与 veth 拓扑，设置地址和 `arp_ignore`，并用 iptables 丢弃内核协议栈的输入/输出/转发，确保报文只经过自建栈。每个检查点脚本负责建网、启动抓包、运行应用、清理资源和生成 transcript。`capture.py` 用 AF_PACKET 记录标准 pcap；`tcp_header.py` 解释 TCP 首部，`retrans.py` 统计重传，`window.py` 统计接收窗口，`fragments.py` 统计分片，`plot_cc.py` 把 `NETSTACK_CC_LOG` 转成 SVG，`fairness.py` 计算 Jain 公平指数。`tcp_tool` 提供固定格式的 source/sink/echo 与同时打开/关闭模式，`ip_tool` 提供分片与原始 IP 流模式。所有应用只使用 POSIX socket 或公开的 IP 接口。

WSL2 内核没有加载 `sch_netem`、`tbf`、`htb` 等 qdisc，`tc` 无法创建这些队列。为了仍然能评估丢包与拥塞，本实现在发送路径提供 `NETSTACK_LOSS`（按百分比丢弃 IPv4 TCP 帧，`NETSTACK_LOSS_SEED` 保证可复现），并在路由器提供令牌桶整形与 FIFO/WFQ 队列。两者都是评估设施，不改变协议语义；真实机器上的 `tc netem` 可以直接替换这部分注入。

**结果。** 各检查点与 Challenge 的原始输出、pcap、日志和图表都在 `lab3/checkpoints/`。

| 项目 | 结果 |
| --- | --- |
| CP8 | 10% 丢包下 200000 字节回显在 3915 ms 内完成并逐字节校验；客户端链路统计 46 个重传段、服务端链路 23 个 |
| CP10 | 四节点链路上官方 perf 程序 10 轮全部完成，吞吐 $4.6$–$7.7$ MB/s，服务端 `all: 1460000` |
| CL3 | 权重 $1:2$ 的两条原始 IP 流，接收端字节比 $1.97$ |
| CL4 | 慢接收端产生 646 个零窗口 ACK，15 s 只读取 660480 字节，发送端被窗口限制在 261121 字节排队 |
| CL5 | Reno 在 20 s 内送达 2187308 字节，cwnd 出现 58 次明显回落 |
| CL6 | BBR 在同一瓶颈下送达 3883600 字节，cwnd 仅 1 次大幅回落，模式序列 `0 → 1 → 2 → 3 → 2` |
| CL7 | 5 条 TCP 流共享瓶颈，Jain 公平指数 $0.9957$ |
| CL8 | w3m 浏览器经代理取回 origin 页面，代理转发 216 字节 |
| CL9 | 21 个单元测试全部通过 |
| CL10 | gcov 行覆盖率 $58.41\%$（单测 + 覆盖插桩的端到端 echo） |

**复现命令。**

```bash
cmake -S . -B build
cmake --build build -j4
bash src/evaluate/run.sh cp7  lab3/checkpoints
bash src/evaluate/run.sh cp8  lab3/checkpoints
bash src/evaluate/run.sh cp9  lab3/checkpoints
bash src/evaluate/run.sh cp10 lab3/checkpoints
bash src/evaluate/run.sh cl1  lab3/checkpoints
bash src/evaluate/run.sh cl2  lab3/checkpoints
bash src/evaluate/run.sh cl3  lab3/checkpoints
bash src/evaluate/run.sh cl4  lab3/checkpoints
bash src/evaluate/run.sh cl5  lab3/checkpoints
bash src/evaluate/run.sh cl6  lab3/checkpoints
bash src/evaluate/run.sh cl7  lab3/checkpoints
bash src/evaluate/run.sh cl8  lab3/checkpoints
bash src/evaluate/run.sh cl9  lab3/checkpoints
bash src/evaluate/run.sh cl10 lab3/checkpoints
```

### Checkpoint 7

`lab3/checkpoints/cp7.txt` 记录了两次节点间的官方 echo 程序运行，并对客户端发出的第一个数据段做了逐字节解释。该包是 20 字节 TCP 首部加 6 字节负载 `hello\n`：

- 源端口 $49152$（`0xc000`），目的端口 $10086$（`0x2766`）；
- 序号与确认号是两端随机初始序号推进后的值；
- 数据偏移字段为 `0x5`，表示首部长度 $5 \times 4 = 20$ 字节，保留位为 0；
- 标志字节 `0x10` 表示 ACK；
- 窗口字段 `0xffff` 表示当前可接收 $65535$ 字节；
- 校验和为 `0x17ab`；伪首部加整个 TCP 段做 16 位反码和的结果为 `0xffff`，校验正确；
- 紧急指针为 0。

### Checkpoint 8

`lab3/checkpoints/cp8.txt` 在两端各注入 10% 的 TCP 丢包（种子 1/2），运行 200000 字节的长度前缀回显。客户端输出 `VERIFIED 200000 bytes in 3915 ms`，说明所有丢失段都被重传并最终按序交付。`retrans.py` 在客户端链路统计到 46 个重复发送的数据段（66882 字节），服务端链路 23 个（33580 字节），并列出重复序号、帧号和时间；`SYN=FIN=1` 说明连接完整建立和关闭。丢包由自建栈的 `NETSTACK_LOSS` 在发送路径注入，原因见 WT6 的环境说明。

### Checkpoint 9

`lab3/checkpoints/cp9.txt` 使用 `ns1 --- ns2 --- ns3 --- ns4` 链路：ns2、ns3 运行 `lab3_router`，ns4 运行未修改的 `echo_server`，ns1 运行未修改的 `echo_client`。链路状态路由在 6 s 内收敛；客户端三轮均输出 `loop #1/#2/#3 ok.`，服务端三次连接都输出 `all: 15000`。抓包摘要显示每条连接双向各 29 个数据段、15000 字节，无 RST；第二连接的 67 个重传来自服务端 `str_echo` 的 1 s sleep（该检查点源码在第二轮故意让服务端每次 read 后 sleep），不是链路错误。

### Checkpoint 10

`lab3/checkpoints/cp10.txt` 在同一四节点拓扑上运行未修改的 `perf_server` 与 `perf_client`。客户端 10 轮均完成，吞吐在 $4.6$–$7.7$ MB/s；服务端在客户端进程退出后收到 FIN 并输出 `all: 1460000`。抓包摘要显示 1041/1046 个数据段、约 1.45 MB 双向负载、无重传和 RST。

### Challenge 1：同时打开与同时关闭

`lab3/checkpoints/cl1.txt` 中两个主机绑定固定端口，并在相同的墙上时钟时刻调用 `connect()`。两端都记录到

```
CLOSED -> SYN_SENT -> SYN_RECEIVED (simultaneous open) -> ESTABLISHED
ESTABLISHED -> FIN_WAIT_1 -> CLOSING (peer fin) -> TIME_WAIT (fin acked)
```

抓包中两个裸 SYN 在 100 µs 内交叉发出，随后是两个 SYN-ACK；关闭时两个 FIN 也交叉。两端都完成了 RFC 793 的同时打开与同时关闭路径。

### Challenge 2：IPv4 分片与重组

`lab3/checkpoints/cl2.txt` 发送一个 6000 字节的原始 IPv4 数据报（协议 253）。抓包显示 5 个分片：标识相同，偏移为 0/1480/2960/4440/5920，前四片 MF=1、最后一片 MF=0，负载为 4×1480+80=6000 字节。接收端重组为 6020 字节（20 字节首部加 6000 字节负载），逐字节模式校验通过。重组器按（源、目的、标识、协议）区分数据报，支持乱序、重复和超时老化。

### Challenge 3：加权公平队列

`lab3/checkpoints/cl3.txt` 使用两个源、一个路由器和一接收端。路由器出接口速率 200000 B/s、队列 32768 B、权重 `10.120.1.1=1`、`10.120.2.1=2`。为了让调度器而非 TCP 拥塞控制决定分配，两个源发送 1000 字节的原始 IP 数据报并保持队列积压。接收端统计为 1328000 与 2618000 字节，比值 $1.97$，与配置的 $1:2$ 一致。调度器采用每流独立队列和差额轮询，每轮量子为 $1500 \times weight$ 字节，轮转指针跨轮持久化，令牌不足时停留在当前流。

### Challenge 4：TCP 流量控制

`lab3/checkpoints/cl4.txt` 中接收端每次只读 1024 字节，然后持续泵送协议栈 20 ms 而不读应用缓冲。抓包中接收端 ACK 的窗口最小为 0，共出现 646 个零窗口 ACK；窗口在 0 与 1024 之间交替，说明应用读取后窗口以小块重新打开。发送端 15 s 只送达 660480 字节，进度显示 261121 字节滞留在发送缓冲、在途为 0，发送被接收窗口限制而不是被丢弃。实现同时设置了窗口字段、在途上限与零窗口探测。

### Challenge 5：Reno 拥塞控制

`lab3/checkpoints/cl5.txt` 与 `cl5-cwnd.svg`：单条 TCP 流经过 200000 B/s、16384 B 队列的 FIFO 路由器，源端每 100 ms 记录一次 cwnd。20 s 内送达 2187308 字节，cwnd 在 1460 与 65535 字节之间变化，出现 58 次明显回落；SVG 显示慢启动上升、丢包后的锯齿和恢复。回落由路由器队列溢出触发，超时把 `ssthresh` 设为在途量的一半并把 `cwnd` 降为 1 MSS。

### Challenge 6：BBR 拥塞控制

`lab3/checkpoints/cl6.txt` 与 `cl6-cwnd.svg`：同一拓扑和瓶颈，设置 `NETSTACK_CC=bbr`。20 s 内送达 3883600 字节，约是 Reno 的 $1.8$ 倍；cwnd 只有 1 次大幅回落，模式序列为 `0(Startup) → 1(Drain) → 2(ProbeBW) → 3(ProbeRTT) → 2`，最终起搏速率 216831 B/s、最小 RTT 12 ms。实现估计送达速率与最小 RTT，按增益计算 `cwnd`，并用令牌桶起搏；没有内核 BBR 的完整带宽过滤器与长期状态，因此结果只说明本实验环境下的行为。

### Challenge 7：五条 TCP 流的公平性

`lab3/checkpoints/cl7.txt`：5 个源经过同一台路由器访问同一个接收端，瓶颈为 500000 B/s、32768 B 的 FIFO 队列。接收端按 peer 统计 25 s 的字节数：

```
1890601, 1603558, 1932906, 1758171, 1745650
```

总和 8930886 字节，Jain 公平指数

$$J = \frac{(\sum x_i)^2}{n \sum x_i^2} = 0.9957,$$

五条流在瓶颈上基本均分。

### Challenge 8：HTTP 代理

`lab3/checkpoints/cl8.txt`：代理在 127.0.0.1:8080 用内核 socket 接受浏览器连接，在 10.140.1.2:80 用自建 TCP 连接源站。浏览器为 w3m（环境中没有 Chrome/Firefox，w3m 由 Ubuntu 包本地解包，未改动系统），`-dump` 输出 origin 页面文本；代理日志显示 `GET http://10.140.1.2/ forwarded=216`，源站日志显示它收到 `GET / HTTP/1.1`。抓包摘要显示代理到源站的 TCP 连接在自建栈上完成 SYN、数据与 FIN。

### Challenge 9：单元测试

`lab3/checkpoints/cl9.txt`：`src/evaluate/unit_tests.cpp` 包含 21 个测试，覆盖 IPv4 首部校验和与篡改检测、TCP 校验和（含奇长度与伪首部依赖）、序号回绕比较、路由的直连/最长前缀/来源优先级/非法掩码/无路由/动态清除、`getaddrinfo` 的数字地址、空参数与错误参数，以及 IPv4 重组的顺序、乱序、缺失和重复分片。测试不需要网络设备或 pcap，输出 `ALL 21 TESTS PASSED`。

### Challenge 10：覆盖率

`lab3/checkpoints/cl10.txt` 与 `cl10-coverage.html`：`NETSTACK_COVERAGE=ON` 用 gcov 插桩构建，先运行 21 个单元测试，再在私有 netns 中运行一次覆盖插桩的 200 KB 端到端回显，最后用 `gcov` 生成每个源文件的 `.gcov`，由 `coverage_report.py` 汇总为 HTML。环境没有 lcov/genhtml，因此报告由 gcov 数据直接生成。总体行覆盖率 $58.41\%$；其中 `routing.cpp` $86.42\%$、`ipfrag.cpp` $76.74\%$、`arp.cpp` $76.80\%$、`link_state.cpp` $83.96\%$、`tcp.cpp` $52.73\%$、`socket.cpp` $56.25\%$。端到端回显覆盖了 TCP 握手、数据、ACK、关闭，以及 IP、ARP、设备与链路状态路径。

### 实验环境与复现

环境为 WSL2 Linux 5.15.167.4、GCC 11.4.0、CMake 3.22.1、libpcap 1.10.7。构建：

```bash
cmake -S . -B build
cmake --build build -j4
```

`src/evaluate/run.sh` 在 `unshare --user --map-root-user --mount --net` 中运行检查点脚本；`/run` 挂载 tmpfs 以支持 `ip netns`，`XTABLES_LOCKFILE` 指向 `/tmp`。每个节点设置 `net.ipv4.conf.all.arp_ignore=8` 并丢弃内核 INPUT/OUTPUT/FORWARD，避免内核代答 ARP、转发或发送 RST；CL8 只丢弃 veth 上的流量，保留 loopback 给浏览器使用。抓包使用 AF_PACKET 的标准 pcap，时间戳来自系统时钟；运行时间使用单调时钟。

复现时 MAC 地址、TCP 初始序号、LRU 标识和链路状态序号由运行环境生成，数值可以不同；丢包种子、拓扑、权重、速率和队列长度由脚本固定。检查点脚本的 `OUT` 目录保存 transcript、应用日志、pcap 与生成的图表。

### Corner Cases

- **字节序与校验和**：所有首部字段按网络字节序写入；TCP 校验和包含 IPv4 伪首部，奇长度负载补零；接收端对首部长度、总长度、校验和和分片字段做边界检查。
- **重复 ACK 与窗口更新**：接收端读取后发送的纯窗口更新不会被误判为重复 ACK；只有窗口字段未变化的零负载 ACK 才参与三次重复 ACK 计数，避免把流控更新当成丢包。
- **关闭时的数据**：单线程栈没有后台发送者，`close()` 在有限时间内泵送排队数据后再发 FIN；进程退出时 `atexit` 关闭所有栈 socket。官方 perf 客户端不显式 close，也能让服务端读到 EOF。
- **丢包与超时**：超时重传按接收窗口重发未确认数据，RTO 指数退避；快速重传在三次真正重复 ACK 后触发；Karn 规则避免用重传段更新 RTT。
- **零窗口**：接收窗口降为 0 后发送端停止普通数据，按 RTO 发送单字节探测；应用读取后窗口以小步重新打开，接收端在增长达到 MSS 时发送窗口更新。
- **路由收敛时序**：检查点客户端进程启动时链路状态可能尚未收敛，`connect()` 在 `ENETUNREACH` 时泵送并重试 5 s。
- **分片**：分片负载按 8 字节对齐；重组按（源、目的、标识、协议）区分，支持乱序、重复与重叠，30 s 老化；转发分片不重组。
- **WFQ 的令牌与量子**：DRR 的轮转指针在令牌不足时停留在当前流，避免首流每次吃掉令牌导致 1:1；每流独立队列上限避免共享尾丢弃饿死某条流。
- **TCP 选项与窗口扩大**：只支持 MSS 选项；不发送窗口扩大，因此对端不会放大窗口；不实现 SACK、时间戳与带外数据。
- **getaddrinfo 笔误**：手册把 `hints->ai_socktype` 写成 `IPPROTO_TCP`，实现按 POSIX 的 `SOCK_STREAM` 校验，并接受 0 与 `SOCK_STREAM`。
- **pcap 捕获**：接收 snap 长度 65535，捕获缓冲 16 MiB；高吞吐下先记录 `ps_drop` 以区分链路丢包与捕获丢包。

### 未实现功能

手册 §3.4.1 明确不要求 TCP 流控、拥塞控制之外的部分以外的功能：套接字选项、带外数据、除 MSS 外的 TCP 选项、URL/域名解析、IP 分片（基础任务）均不在必需范围。本实现完成了基础任务与 Bonus PT5/WT6，以及 CL1–CL10；`not-implemented.pdf` 因此为空文件。CL11（自选题目）未在本报告中实现。

### 提交内容

- `lab3-wt.md`：本报告（对应提交目录中的 `README.pdf`）。
- `src/`：协议栈、路由器、HTTP 代理、评估程序与单元测试。
- `lab3/checkpoints/`：CP7–CP10 与 CL1–CL10 的 transcript、pcap、日志、SVG 图表和覆盖率 HTML。
- `lab3/CMakeLists.txt`：提交目录的构建入口。
- `lab3/not-implemented.pdf`：空文件（所有规定功能已完成）。
