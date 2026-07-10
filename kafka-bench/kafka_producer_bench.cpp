// kafka_producer_bench.cpp
// 基于 librdkafka C++ 的 Kafka 发送端(producer)性能上限压测工具。
//
// 用途:
//   - 用你们真实的 librdkafka 客户端 + 自定义配置,测出发送端的真实吞吐上限(Step 2 / 上限 B)
//   - 所有 Kafka 参数通过 -X key=value 传入,与生产配置保持一致或做参数扫描
//
// 依赖: librdkafka (C++)  头文件 <librdkafka/rdkafkacpp.h>
// 编译:
//   g++ -O2 -std=c++17 kafka_producer_bench.cpp -o kafka_producer_bench -lrdkafka++ -lrdkafka -lpthread
//
// 说明:
//   默认采用"背压模式"——发送队列满时不丢弃、而是 poll 等待再继续,
//   这样测出的稳态吞吐就是发送端的真实上限。
//   加 -D 可切换为"满即丢弃并计数"模式,用于复现线上丢消息现象。

#include <librdkafka/rdkafkacpp.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

typedef unsigned long long ull;

static std::atomic<bool> g_run{true};
static void on_sig(int) { g_run = false; }

// 投递报告回调:统计成功/失败(失败即"本应丢弃"的消息)
class DrCb : public RdKafka::DeliveryReportCb {
public:
  std::atomic<ull> ok{0};
  std::atomic<ull> err{0};
  std::atomic<ull> ok_bytes{0};
  void dr_cb(RdKafka::Message &m) override {
    if (m.err()) {
      err.fetch_add(1, std::memory_order_relaxed);
    } else {
      ok.fetch_add(1, std::memory_order_relaxed);
      ok_bytes.fetch_add(m.len(), std::memory_order_relaxed);
    }
  }
};

// 事件回调:打印 broker 错误 / 可选打印 statistics JSON
class EvCb : public RdKafka::EventCb {
public:
  bool print_stats;
  explicit EvCb(bool ps) : print_stats(ps) {}
  void event_cb(RdKafka::Event &e) override {
    switch (e.type()) {
      case RdKafka::Event::EVENT_ERROR:
        fprintf(stderr, "%% ERROR: %s: %s\n",
                RdKafka::err2str(e.err()).c_str(), e.str().c_str());
        break;
      case RdKafka::Event::EVENT_STATS:
        if (print_stats) fprintf(stderr, "%% STATS: %s\n", e.str().c_str());
        break;
      default:
        break;
    }
  }
};

static void usage(const char *prog) {
  fprintf(stderr,
    "用法: %s -b <brokers> -t <topic> [选项] [-X key=value ...]\n"
    "  -b <brokers>     必填, 如 10.0.0.1:9092,10.0.0.2:9092\n"
    "  -t <topic>       必填, 目标 topic(分区数在建 topic 时设置)\n"
    "  -s <bytes>       单条消息大小, 默认 1024\n"
    "  -c <count>       发送总条数, 默认 5000000; 设 0 则按时长跑\n"
    "  -T <seconds>     按时长跑(秒), 覆盖 -c\n"
    "  -r <seconds>     实时报告间隔, 默认 2\n"
    "  -D               队列满时丢弃并计数(复现丢消息); 默认背压等待\n"
    "  -S               打印 librdkafka statistics JSON(需配 -X statistics.interval.ms=2000)\n"
    "  -X key=value     透传任意 librdkafka 配置(可多次), 如:\n"
    "                     -X acks=1 -X linger.ms=10 -X compression.codec=lz4\n"
    "                     -X batch.num.messages=10000 -X batch.size=1000000\n"
    "                     -X queue.buffering.max.messages=1000000\n"
    "                     -X queue.buffering.max.kbytes=1048576\n",
    prog);
}

int main(int argc, char **argv) {
  std::string brokers, topic;
  size_t msg_size = 1024;
  ull total = 5000000;
  int duration = 0;
  double report = 2.0;
  bool drop_on_full = false;
  bool print_stats = false;
  std::vector<std::pair<std::string, std::string>> xconf;

  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto need = [&](const char *n) -> std::string {
      if (i + 1 >= argc) { fprintf(stderr, "缺少 %s 的取值\n", n); exit(1); }
      return argv[++i];
    };
    if (a == "-b") brokers = need("-b");
    else if (a == "-t") topic = need("-t");
    else if (a == "-s") msg_size = strtoull(need("-s").c_str(), nullptr, 10);
    else if (a == "-c") total = strtoull(need("-c").c_str(), nullptr, 10);
    else if (a == "-T") duration = atoi(need("-T").c_str());
    else if (a == "-r") report = atof(need("-r").c_str());
    else if (a == "-D") drop_on_full = true;
    else if (a == "-S") print_stats = true;
    else if (a == "-X") {
      std::string kv = need("-X");
      auto p = kv.find('=');
      if (p == std::string::npos) { fprintf(stderr, "-X 需要 key=value\n"); return 1; }
      xconf.emplace_back(kv.substr(0, p), kv.substr(p + 1));
    } else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
    else { fprintf(stderr, "未知参数: %s\n", a.c_str()); usage(argv[0]); return 1; }
  }

  if (brokers.empty() || topic.empty()) { usage(argv[0]); return 1; }

  std::string errstr;
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
  if (conf->set("bootstrap.servers", brokers, errstr) != RdKafka::Conf::CONF_OK) {
    fprintf(stderr, "%s\n", errstr.c_str()); return 1;
  }

  DrCb dr;
  EvCb ev(print_stats);
  conf->set("dr_cb", &dr, errstr);
  conf->set("event_cb", &ev, errstr);

  // 应用用户透传的所有 librdkafka 配置
  for (auto &kv : xconf) {
    if (conf->set(kv.first, kv.second, errstr) != RdKafka::Conf::CONF_OK) {
      fprintf(stderr, "配置失败 %s=%s : %s\n", kv.first.c_str(), kv.second.c_str(), errstr.c_str());
      return 1;
    }
  }

  RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
  if (!producer) { fprintf(stderr, "创建 producer 失败: %s\n", errstr.c_str()); return 1; }
  delete conf;

  std::vector<char> payload(msg_size, 'x');
  signal(SIGINT, on_sig);
  signal(SIGTERM, on_sig);

  fprintf(stderr, "开始压测: brokers=%s topic=%s 消息大小=%zuB 模式=%s\n",
          brokers.c_str(), topic.c_str(), msg_size,
          drop_on_full ? "满即丢弃" : "背压等待");

  using clock = std::chrono::steady_clock;
  auto start = clock::now();
  auto last = start;
  ull last_ok = 0, sent = 0, dropped = 0;

  while (g_run) {
    if (duration > 0) {
      if (std::chrono::duration<double>(clock::now() - start).count() >= duration) break;
    } else if (sent >= total) {
      break;
    }

    RdKafka::ErrorCode err = producer->produce(
        topic, RdKafka::Topic::PARTITION_UA,
        RdKafka::Producer::RK_MSG_COPY,
        payload.data(), payload.size(),
        nullptr, 0,    // key
        0,             // timestamp(0=当前)
        nullptr);      // opaque

    if (err == RdKafka::ERR_NO_ERROR) {
      sent++;
      producer->poll(0);
    } else if (err == RdKafka::ERR__QUEUE_FULL) {
      if (drop_on_full) {
        dropped++;
        producer->poll(0);
      } else {
        // 背压:等待队列被发送线程排空,再由下一轮重发(不计入 sent)
        producer->poll(10);
      }
    } else {
      fprintf(stderr, "produce 失败: %s\n", RdKafka::err2str(err).c_str());
      producer->poll(0);
    }

    auto now = clock::now();
    double dt = std::chrono::duration<double>(now - last).count();
    if (dt >= report) {
      ull cok = dr.ok.load();
      double rate = (cok - last_ok) / dt;
      fprintf(stderr,
        "[%4.0fs] 已投递=%llu  速率=%.0f msg/s (%.1f MB/s)  失败=%llu  队列积压=%d  丢弃=%llu\n",
        std::chrono::duration<double>(now - start).count(),
        (ull)cok, rate, rate * msg_size / 1e6,
        (ull)dr.err.load(), producer->outq_len(), (ull)dropped);
      last = now;
      last_ok = cok;
    }
  }

  fprintf(stderr, "生产结束, flush 中...\n");
  producer->flush(30000);

  double elapsed = std::chrono::duration<double>(clock::now() - start).count();
  ull ok = dr.ok.load(), errc = dr.err.load(), okb = dr.ok_bytes.load();

  printf("\n==== 结果 ====\n");
  printf("elapsed_s            = %.2f\n", elapsed);
  printf("delivered            = %llu\n", (ull)ok);
  printf("failed(dr_err)       = %llu\n", (ull)errc);
  printf("dropped_on_full      = %llu\n", (ull)dropped);
  printf("msg_size_bytes       = %zu\n", msg_size);
  printf("avg_throughput_msg_s = %.0f\n", ok / elapsed);
  printf("avg_throughput_MB_s  = %.2f\n", okb / elapsed / 1e6);
  printf("(注:以运行中稳态的实时 msg/s 为发送端上限的准确值, 末尾为含 flush 的平均值)\n");
  printf("config:");
  for (auto &kv : xconf) printf(" %s=%s", kv.first.c_str(), kv.second.c_str());
  printf("\n");

  delete producer;
  return errc > 0 || dropped > 0 ? 2 : 0;
}
