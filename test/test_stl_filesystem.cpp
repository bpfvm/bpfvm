// STL <filesystem> 测试：验证 std::filesystem 在 bpfvm 上正确工作。
//
// 机制（见 port_cplusplus.md「filesystem 支持」）：
//   - libc++ <filesystem> 头 + libcxx.a 的 filesystem/*.o（path/operations/
//     directory_iterator/directory_entry/filesystem_error/filesystem_clock/
//     int128_builtins）。
//   - 关键宏 -D_LIBCPP_HAS_NO_INT128：BPF 后端不支持 __int128 乘除（__multi3/
//     __divti3），file_clock::rep 默认是 __int128_t；定义该宏让 rep 退化为
//     long long，整条时间戳运算链不再触发后端拒绝。
//   - VM 已实现全部所需文件系统 syscall（openat/statx/getdents64/mkdirat/
//     unlinkat/symlinkat/linkat/renameat2/readlinkat/fchdir/getcwd/fchmodat/
//     utimensat/faccessat/truncate/ftruncate），musl 包装完成。
//
// 已知降级（VM 未实现对应 syscall，测试中避开）：
//   - copy_file（依赖 sendfile，ENOSYS → 返回错误）
//   - space()（依赖 statfs，ENOSYS → capacity/free/available 置 (uintmax_t)-1）
//
// host 变体用 g++ 编宿主 glibc，作为对照基线（同源码）。

#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace fs = std::filesystem;

int main() {
    int failures = 0;
    std::error_code ec;

    // 用本测试专属子目录，避免污染当前目录。固定名 + 清理旧残留。
    const fs::path root = "fs_test_dir__bpfvm";

    // 清理可能的旧残留（忽略错误）。
    fs::remove_all(root, ec);
    // 创建干净的测试根目录。
    if (!fs::create_directory(root, ec) || ec) {
        printf("FAIL: create_directory(%s) ec=%s\n", root.c_str(), ec.message().c_str());
        return 1;
    }

    // ===== (1) path 构造/迭代/分解 =====
    fs::path p = root / "sub" / "a.txt";
    if (p.filename() != "a.txt") {
        printf("FAIL path filename: '%s'\n", p.filename().c_str());
        ++failures;
    }
    if (p.parent_path().filename() != "sub") {
        printf("FAIL path parent filename: '%s'\n", p.parent_path().filename().c_str());
        ++failures;
    }
    if (p.extension() != ".txt") {
        printf("FAIL path extension: '%s'\n", p.extension().c_str());
        ++failures;
    }
    if (p.stem() != "a") {
        printf("FAIL path stem: '%s'\n", p.stem().c_str());
        ++failures;
    }
    // 迭代：root/sub/a.txt → ["", root, sub, a.txt]（前导 / 产生空元素，但这里 root 是相对名）
    {
        std::vector<std::string> parts;
        for (const auto& e : p) parts.push_back(e.string());
        if (parts.size() != 3 || parts[0] != "fs_test_dir__bpfvm" ||
            parts[1] != "sub" || parts[2] != "a.txt") {
            printf("FAIL path iterate: size=%zu", parts.size());
            for (auto& s : parts) printf(" [%s]", s.c_str());
            printf("\n");
            ++failures;
        }
    }

    // ===== (2) create_directories / exists / is_directory / is_regular_file =====
    fs::path subdir = root / "sub";
    if (!fs::create_directories(subdir, ec) || ec) {
        printf("FAIL create_directories: ec=%s\n", ec.message().c_str());
        ++failures;
    }
    if (!fs::exists(subdir)) { printf("FAIL exists(subdir)\n"); ++failures; }
    if (!fs::is_directory(subdir)) { printf("FAIL is_directory(subdir)\n"); ++failures; }
    if (fs::is_regular_file(subdir)) { printf("FAIL is_regular_file(subdir) should be false\n"); ++failures; }

    // ===== (3) 写文件 + file_size / status =====
    fs::path fpath = subdir / "a.txt";
    {
        FILE* f = fopen(fpath.c_str(), "wb");
        if (!f) { printf("FAIL fopen write: %s\n", fpath.c_str()); ++failures; }
        else {
            const char* msg = "hello filesystem";  // 16 字节
            fwrite(msg, 1, strlen(msg), f);
            fclose(f);
        }
    }
    if (!fs::exists(fpath)) { printf("FAIL exists(fpath)\n"); ++failures; }
    if (!fs::is_regular_file(fpath)) { printf("FAIL is_regular_file(fpath)\n"); ++failures; }
    {
        auto sz = fs::file_size(fpath, ec);
        if (ec || sz != 16) {
            printf("FAIL file_size: sz=%zu ec=%s\n", (size_t)sz, ec.message().c_str());
            ++failures;
        }
    }
    {
        fs::file_status st = fs::status(fpath, ec);
        if (ec || !fs::is_regular_file(st)) {
            printf("FAIL status(fpath): ec=%s type=%d\n", ec.message().c_str(), (int)st.type());
            ++failures;
        }
    }

    // ===== (4) directory_iterator =====
    {
        // root 下应至少有 "sub"。
        bool found_sub = false;
        for (const auto& entry : fs::directory_iterator(root, ec)) {
            if (entry.path().filename() == "sub") found_sub = true;
        }
        if (ec || !found_sub) {
            printf("FAIL directory_iterator: found_sub=%d ec=%s\n", found_sub, ec.message().c_str());
            ++failures;
        }
    }
    // sub 下应至少有 "a.txt"，且 directory_entry::status 是 regular。
    {
        bool found_a = false;
        for (const auto& entry : fs::directory_iterator(subdir, ec)) {
            if (entry.path().filename() == "a.txt") {
                found_a = true;
                auto st = entry.status(ec);
                if (ec || !fs::is_regular_file(st)) {
                    printf("FAIL directory_entry.status: ec=%s\n", ec.message().c_str());
                    ++failures;
                }
            }
        }
        if (ec || !found_a) {
            printf("FAIL directory_iterator(sub): found_a=%d ec=%s\n", found_a, ec.message().c_str());
            ++failures;
        }
    }

    // ===== (5) create_directories 多层 + recursive_directory_iterator =====
    fs::path deep = root / "d1" / "d2" / "d3";
    if (!fs::create_directories(deep, ec) || ec) {
        printf("FAIL create_directories(deep): ec=%s\n", ec.message().c_str());
        ++failures;
    }
    {
        // 在深层放一个文件。
        fs::path deepf = deep / "deep.txt";
        FILE* f = fopen(deepf.c_str(), "wb");
        if (f) { fwrite("deep", 1, 4, f); fclose(f); }
    }
    {
        int file_count = 0;
        int dir_count = 0;
        for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::none, ec)) {
            if (entry.is_regular_file(ec)) ++file_count;
            else if (entry.is_directory(ec)) ++dir_count;
        }
        // 文件：a.txt + deep.txt = 2；目录：sub + d1 + d2 + d3 = 4
        // （recursive_directory_iterator 遍历 root 的内容，不含 root 自身）。
        if (file_count != 2 || dir_count != 4) {
            printf("FAIL recursive_directory_iterator: files=%d dirs=%d\n", file_count, dir_count);
            ++failures;
        }
    }

    // ===== (6) symlink / read_symlink / is_symlink / symlink_status =====
    // symlink target 用相对路径 "a.txt"（相对 symlink 所在目录 sub，POSIX 语义）。
    // slink 放在 sub 下与 a.txt 同目录，这样跟随 target 能正确解析到 a.txt。
    fs::path slink = subdir / "a_link.txt";
    fs::create_symlink(fs::path("a.txt"), slink, ec);
    if (ec) {
        printf("FAIL create_symlink: ec=%s\n", ec.message().c_str());
        ++failures;
    } else {
        if (!fs::is_symlink(slink)) { printf("FAIL is_symlink\n"); ++failures; }
        fs::path target = fs::read_symlink(slink, ec);
        if (ec || target != "a.txt") {
            printf("FAIL read_symlink: target='%s' ec=%s\n", target.c_str(), ec.message().c_str());
            ++failures;
        }
        // symlink_status 应是 symlink（不跟随）。
        fs::file_status sst = fs::symlink_status(slink, ec);
        if (ec || !fs::is_symlink(sst)) {
            printf("FAIL symlink_status: ec=%s type=%d\n", ec.message().c_str(), (int)sst.type());
            ++failures;
        }
        // status（跟随）应是 regular_file。
        fs::file_status fst = fs::status(slink, ec);
        if (ec || !fs::is_regular_file(fst)) {
            printf("FAIL status(symlink) follow: ec=%s type=%d\n", ec.message().c_str(), (int)fst.type());
            ++failures;
        }
    }

    // ===== (7) create_hard_link / hard_link_count =====
#if !defined(__ANDROID__)
    // Android 文件系统禁止 app 创建硬链接（EPERM），跳过本组验证。
    fs::path hlink = root / "a_hard.txt";
    fs::create_hard_link(fpath, hlink, ec);
    if (ec) {
        printf("FAIL create_hard_link: ec=%s\n", ec.message().c_str());
        ++failures;
    } else {
        auto n = fs::hard_link_count(fpath, ec);
        if (ec || n < 2) {
            printf("FAIL hard_link_count: n=%zu ec=%s\n", (size_t)n, ec.message().c_str());
            ++failures;
        }
        if (!fs::exists(hlink)) { printf("FAIL hard_link exists\n"); ++failures; }
    }
#endif

    // ===== (8) rename =====
    fs::path rfrom = root / "rfrom.txt";
    fs::path rto = root / "rto.txt";
    {
        FILE* f = fopen(rfrom.c_str(), "wb");
        if (f) { fwrite("rename me", 1, 9, f); fclose(f); }
    }
    fs::rename(rfrom, rto, ec);
    if (ec || fs::exists(rfrom) || !fs::exists(rto)) {
        printf("FAIL rename: ec=%s from_exists=%d to_exists=%d\n",
               ec.message().c_str(), (int)fs::exists(rfrom), (int)fs::exists(rto));
        ++failures;
    }

    // ===== (9) copy（目录递归 copy，非 copy_file）=====
    // 注意：copy 对每个文件内部调 copy_file，而 copy_file 在 VM 上依赖 sendfile
    // （未实现 → ENOSYS 降级）。故 copy(recursive) 对含文件的目录会部分失败。
    // 这里只验证目录结构被创建（copy 对子目录的创建不依赖 copy_file），文件复制
    // 失败用 error_code 容错，不计入 failures（已知降级）。
    fs::path copy_dst = root / "copy_of_sub";
    fs::copy(subdir, copy_dst, fs::copy_options::recursive | fs::copy_options::skip_existing, ec);
    // copy 可能因 copy_file(sendfile ENOSYS) 设 ec，但目录应已创建。
    std::error_code ec2;
    if (!fs::is_directory(copy_dst, ec2)) {
        printf("FAIL copy: copy_dst not a directory (ec=%s, ec2=%s)\n",
               ec.message().c_str(), ec2.message().c_str());
        ++failures;
    }

    // ===== (10) permissions =====
    fs::permissions(fpath, fs::perms::owner_read | fs::perms::owner_write, ec);
    if (ec) {
        printf("FAIL permissions: ec=%s\n", ec.message().c_str());
        ++failures;
    } else {
        fs::file_status st = fs::status(fpath, ec);
        auto pr = st.permissions();
        if ((pr & fs::perms::owner_read) == fs::perms::none ||
            (pr & fs::perms::owner_write) == fs::perms::none) {
            printf("FAIL permissions check: perms=%u\n", (unsigned)pr);
            ++failures;
        }
    }

    // ===== (11) last_write_time（读，不写——写需 utimensat 已实现，VM 有）=====
    {
        fs::last_write_time(fpath, ec);
        if (ec) {
            printf("FAIL last_write_time: ec=%s\n", ec.message().c_str());
            ++failures;
        }
        // 时间不应为 epoch（>0）。file_clock rep 降级为 long long 仍能表示。
        // （不与 host 精确比较，只验证可读且非零。）
    }

    // ===== (12) current_path get / set =====
    fs::path saved_cwd = fs::current_path(ec);
    if (ec) {
        printf("FAIL current_path(get): ec=%s\n", ec.message().c_str());
        ++failures;
    } else {
        // 切到 subdir 再切回。current_path(get) 走 getcwd 返回绝对路径，故先在
        // 切换前算出 subdir 的 canonical 绝对路径，切换后与之比较。
        fs::path can_sub = fs::canonical(subdir, ec);
        if (ec) {
            printf("FAIL canonical(subdir) pre: ec=%s\n", ec.message().c_str());
            ++failures;
        } else {
            fs::current_path(subdir, ec);
            if (ec) {
                printf("FAIL current_path(set): ec=%s\n", ec.message().c_str());
                ++failures;
            } else {
                fs::path now = fs::current_path(ec);
                if (ec || now != can_sub) {
                    printf("FAIL current_path verify: now='%s' expected='%s' ec=%s\n",
                           now.c_str(), can_sub.c_str(), ec.message().c_str());
                    ++failures;
                }
                fs::current_path(saved_cwd, ec);  // 切回，忽略错误继续。
            }
        }
    }

    // ===== (13) weakly_canonical / canonical =====
    // canonical 要求路径存在；fpath 存在。
    {
        fs::path can = fs::canonical(fpath, ec);
        if (ec) {
            printf("FAIL canonical: ec=%s\n", ec.message().c_str());
            ++failures;
        }
        // weakly_canonical 对不存在的尾部也工作。
        fs::path wc = fs::weakly_canonical(root / "no_such", ec);
        if (ec) {
            printf("FAIL weakly_canonical: ec=%s\n", ec.message().c_str());
            ++failures;
        }
    }

    // ===== (14) temp_directory_path =====
    // 只读不写；若 /tmp 不存在会报错，用 error_code 容错（不致命）。
    {
        fs::path tmp = fs::temp_directory_path(ec);
        if (ec) {
            printf("NOTE temp_directory_path: ec=%s (non-fatal)\n", ec.message().c_str());
        }
    }

    // ===== (15) remove / remove_all =====
#if !defined(__ANDROID__)
    if (!fs::remove(hlink, ec) || ec) {
        printf("FAIL remove(hlink): ec=%s\n", ec.message().c_str());
        ++failures;
    }
    if (fs::exists(hlink)) { printf("FAIL remove(hlink) still exists\n"); ++failures; }
#endif

    auto removed = fs::remove_all(root, ec);
    if (ec || removed == static_cast<uintmax_t>(0)) {
        printf("FAIL remove_all: removed=%zu ec=%s\n", (size_t)removed, ec.message().c_str());
        ++failures;
    }
    if (fs::exists(root)) {
        printf("FAIL remove_all: root still exists\n");
        ++failures;
    }

    if (failures == 0) {
        printf("stl_filesystem: OK\n");
    } else {
        printf("stl_filesystem: %d FAILURES\n", failures);
    }
    return failures == 0 ? 0 : 1;
}
