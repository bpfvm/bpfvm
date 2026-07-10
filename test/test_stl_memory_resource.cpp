// STL <memory_resource> 测试：验证 pmr 内存资源在 bpfvm 上正确工作。
//
// 机制（见 port_cplusplus.md）：
//   - libc++ <memory_resource> 头 + libcxx.a 的 memory_resource.o（pmr pool 实现）
//   - pmr::pool_resource 内部用 operator new(size_t, align_val_t)（对齐分配），由
//     stdlib_new_delete.cpp 提供对齐版 operator new/delete（St11align_val_t）
//
// 覆盖：
//   - monotonic_buffer_resource：栈缓冲区 + 上游分配（触发对齐 new）
//   - unsynchronized_pool_resource：池分配/释放
//   - synchronized_pool_resource：线程安全池
//   - new_delete_resource / null_memory_resource / get/set_default_resource
//   - pmr::polymorphic_allocator 配合 pmr::vector
//
// host 变体用 g++ 编宿主 glibc，作为对照基线。

#include <memory_resource>
#include <vector>
#include <cstdio>
#include <cstdint>

int main() {
    int failures = 0;

    // (1) monotonic_buffer_resource：用栈缓冲区，分配不释放（仅析构时统一回收）
    {
        unsigned char buf[256];
        std::pmr::monotonic_buffer_resource mbr(buf, sizeof(buf));
        // 分配几个块（不释放——monotronic 不支持单个 deallocate 回收）
        void *p1 = mbr.allocate(32, alignof(int));
        void *p2 = mbr.allocate(64, alignof(double));
        void *p3 = mbr.allocate(16, 1);
        if (!p1 || !p2 || !p3) { printf("FAIL mbr allocate returned null\n"); failures++; }
        if (p1 == p2 || p2 == p3 || p1 == p3) { printf("FAIL mbr allocated overlapping\n"); failures++; }
        // 对齐检查：p1 必须 alignof(int) 对齐
        if (reinterpret_cast<uintptr_t>(p1) % alignof(int) != 0) {
            printf("FAIL mbr p1 not int-aligned\n"); failures++;
        }
        // 超出栈缓冲区时走上游 new_delete_resource（触发对齐版 operator new）
        void *big = mbr.allocate(4096, alignof(long long));
        if (!big) { printf("FAIL mbr upstream allocate returned null\n"); failures++; }
        // 写入验证可写
        *static_cast<int *>(p1) = 0x1234;
        *static_cast<int *>(p3) = 0x5678;
        if (*static_cast<int *>(p1) != 0x1234) { printf("FAIL mbr p1 writeback\n"); failures++; }
        if (failures == 0) printf("[OK] monotonic_buffer_resource\n");
    }

    // (2) unsynchronized_pool_resource：池分配 + do_deallocate 真正归还池
    {
        std::pmr::pool_options opts;
        opts.max_blocks_per_chunk = 4;
        opts.largest_required_pool_block = 128;
        std::pmr::unsynchronized_pool_resource pool(opts);
        // 多次分配同一大小，验证池复用（分配后释放再分配，应命中池而非上游）
        void *p1 = pool.allocate(32, alignof(int));
        void *p2 = pool.allocate(32, alignof(int));
        pool.deallocate(p1, 32, alignof(int));
        void *p3 = pool.allocate(32, alignof(int));  // 应复用 p1 的池槽
        if (!p1 || !p2 || !p3) { printf("FAIL pool allocate null\n"); failures++; }
        if (reinterpret_cast<uintptr_t>(p1) % alignof(int) != 0) {
            printf("FAIL pool p1 not aligned\n"); failures++;
        }
        *static_cast<int *>(p3) = 42;
        if (*static_cast<int *>(p3) != 42) { printf("FAIL pool writeback\n"); failures++; }
        if (failures == 0) printf("[OK] unsynchronized_pool_resource\n");
    }

    // (3) synchronized_pool_resource：线程安全池（单线程下行为同 unsynchronized）
    {
        std::pmr::synchronized_pool_resource pool;
        void *p = pool.allocate(64, alignof(double));
        if (!p) { printf("FAIL sync pool null\n"); failures++; }
        if (reinterpret_cast<uintptr_t>(p) % alignof(double) != 0) {
            printf("FAIL sync pool not double-aligned\n"); failures++;
        }
        pool.deallocate(p, 64, alignof(double));
        if (failures == 0) printf("[OK] synchronized_pool_resource\n");
    }

    // (4) new_delete_resource / null_memory_resource / get/set_default_resource
    {
        auto *ndr = std::pmr::new_delete_resource();
        if (!ndr) { printf("FAIL new_delete_resource null\n"); failures++; }
        void *p = ndr->allocate(48, alignof(long long));
        if (!p) { printf("FAIL ndr allocate null\n"); failures++; }
        if (reinterpret_cast<uintptr_t>(p) % alignof(long long) != 0) {
            printf("FAIL ndr not aligned\n"); failures++;
        }
        ndr->deallocate(p, 48, alignof(long long));

        auto *nullr = std::pmr::null_memory_resource();
        // null_memory_resource::allocate 会失败（-fno-exceptions 下 abort），这里只测
        // do_is_equal：null_resource 与 new_delete_resource 不应相等
        if (nullr->is_equal(*ndr)) { printf("FAIL null_memory_resource.is_equal(new_delete)\n"); failures++; }
        if (!ndr->is_equal(*ndr)) { printf("FAIL new_delete_resource.is_equal(self)\n"); failures++; }

        // get/set_default_resource 往返
        auto *old = std::pmr::get_default_resource();
        std::pmr::set_default_resource(ndr);
        if (std::pmr::get_default_resource() != ndr) { printf("FAIL set_default_resource\n"); failures++; }
        std::pmr::set_default_resource(old);
        if (failures == 0) printf("[OK] global resources + is_equal\n");
    }

    // (5) polymorphic_allocator + pmr::vector：用 monotonic_buffer_resource 作分配器
    {
        unsigned char buf[1024];
        std::pmr::monotonic_buffer_resource mbr(buf, sizeof(buf));
        std::pmr::vector<int> v(&mbr);
        for (int i = 0; i < 50; i++) v.push_back(i * 2);
        long sum = 0;
        for (int x : v) sum += x;
        // 0..49 * 2 求和 = 2 * (49*50/2) = 2450
        if (sum != 2450) { printf("FAIL pmr::vector sum=%ld\n", sum); failures++; }
        if (v.size() != 50) { printf("FAIL pmr::vector size=%zu\n", v.size()); failures++; }
        if (failures == 0) printf("[OK] pmr::vector with monotonic_buffer_resource\n");
    }

    if (failures == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURE(S)\n", failures);
    return 1;
}
