// termcap_shim.c — musl/BPF 环境的最小 termcap 实现，编进 libreadline.a。
//
// readline 8.2 的终端能力获取只经 6 个入口：tgetent/tgetstr/tgetnum/tgetflag/
// tputs/tgoto（cap 清单见 readline/terminal.c 的 tc_strings 表与 co/li/am/xn/km）。
// 条目内置（不读 /etc/termcap）：xterm 系彩色终端一份（xterm/screen/tmux/rxvt/
// linux/ansi 及 -256color 变体共用，ESC[ 序列彼此兼容）、vt100 子集、dumb。
// 未知 TERM 返回 0，readline 退化为整行重画模式（编辑功能仍在）。
//
// tgoto 参数序按 ncurses 实测行为：先消费第二参数。readline 仅以
// tgoto(IC, 0, col)（取 col）与 tgoto(DC, count, count)（两参相同）调用，
// cm 类光标串 readline 不用，故该序对现有调用全成立。
//
// 用法：clang ${COMMON_CFLAGS//-g/} -c scripts/termcap_shim.c，.o 并入
// libreadline.a；configure 以 bash_cv_termcap_lib=libc 预置缓存跳过库探测。

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// termcap 文本格式：":id=value:"（串，\E/^X/八进制转义）、":id#n:"（数）、":id:"（标志）
static const char kColorTerm[] =
    ":am:xn:co#80:li#24:"
    "@7=\\EOF:AL=\\E[%dL:DC=\\E[%dP:DL=\\E[%dM:E3=\\E[3J:IC=\\E[%d@:"
    "al=\\E[L:bl=^G:cd=\\E[J:ce=\\E[K:cl=\\E[H\\E[2J:cr=^M:"
    "dc=\\E[P:dl=\\E[M:ho=\\E[H:ic=\\E[@:"
    "kD=\\E[3~:kH=\\EOF:kI=\\E[2~:kN=\\E[6~:kP=\\E[5~:"
    "kd=\\EOB:ke=\\E[?1l\\E>:kh=\\EOH:kl=\\EOD:kr=\\EOC:ks=\\E[?1h\\E=:ku=\\EOA:"
    "le=^H:md=\\E[1m:me=\\E[m:mr=\\E[7m:nd=\\E[C:"
    "se=\\E[27m:so=\\E[7m:ue=\\E[24m:up=\\E[A:us=\\E[4m:"
    "ve=\\E[?25h:vs=\\E[?25l:";

static const char kVt100[] =
    ":am:co#80:li#24:"
    "bl=^G:cd=\\E[J:ce=\\E[K:cl=\\E[2J:cr=^M:"
    "dc=\\E[P:dl=\\E[M:ho=\\E[H:ic=\\E[@:"
    "kD=\\E[3~:kH=\\EOF:kN=\\E[6~:kP=\\E[5~:"
    "kd=\\EOB:kh=\\E[H:kl=\\EOD:kr=\\EOC:ku=\\EOA:"
    "le=^H:nd=\\E[C:se=\\E[27m:so=\\E[7m:up=\\E[A:";

static const char kDumb[] = ":co#80:cr=^M:";

static const char *g_entry = NULL;

// 名字归一：截掉首个 '-' 之后与 '.' 之后的部分再匹配（xterm-256color -> xterm）
static const char *pick_entry(const char *name) {
    static const struct { const char *n; const char *e; } tab[] = {
        { "xterm", kColorTerm }, { "screen", kColorTerm },
        { "tmux",   kColorTerm }, { "rxvt",   kColorTerm },
        { "linux",  kColorTerm }, { "ansi",   kColorTerm },
        { "vt100",  kVt100 },    { "vt220",  kVt100 },
        { "dumb",   kDumb },
    };
    char norm[32];
    size_t n = 0;
    while (name[n] && name[n] != '-' && name[n] != '.' && n < sizeof(norm) - 1) n++;
    memcpy(norm, name, n);
    norm[n] = '\0';
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++)
        if (strcmp(norm, tab[i].n) == 0) return tab[i].e;
    return NULL;
}

int tgetent(char *bp, const char *name) {
    (void)bp;   // 兼容签名：条目由内部静态指针持有，不落调用方缓冲
    if (name == NULL || *name == '\0') {
        g_entry = kDumb;
        return 0;
    }
    g_entry = pick_entry(name);
    if (g_entry == NULL) {
        g_entry = kDumb;
        return 0;
    }
    return 1;
}

// 找 :id 形式的字段，返回 id 之后的字符位置（':' 标志 / '=' 串 / '#' 数 / '@' 取消）
static const char *find_field(const char *id) {
    if (g_entry == NULL) return NULL;
    size_t idlen = strlen(id);
    const char *p = g_entry - 1;
    while ((p = strchr(p + 1, ':')) != NULL) {
        const char *f = p + 1;
        if (strncmp(f, id, idlen) != 0) continue;
        char c = f[idlen];
        if (c == ':' || c == '=' || c == '#' || c == '@') return f + idlen;
    }
    return NULL;
}

// 解码字段体到 out，返回写完的位置（不含 NUL）
static char *decode(const char *s, char *out) {
    while (*s != '\0' && *s != ':') {
        if (*s == '\\' && s[1] != '\0') {
            s++;
            if (*s == 'E' || *s == 'e')      *out++ = 27;
            else if (*s == 'n')              *out++ = '\n';
            else if (*s == 'r')              *out++ = '\r';
            else if (*s == 't')              *out++ = '\t';
            else if (*s == 'b')              *out++ = '\b';
            else if (*s == 'f')              *out++ = '\f';
            else if (*s == 's')              *out++ = ' ';
            else if (*s >= '0' && *s <= '7') {
                int v = 0, k = 0;
                while (k < 3 && *s >= '0' && *s <= '7') { v = v * 8 + (*s - '0'); s++; k++; }
                *out++ = (char)v;
                continue;
            }
            else                            *out++ = *s;   // \: \\ \, 等
            s++;
        } else if (*s == '^' && s[1] != '\0') {
            s++;
            *out++ = (*s == '?') ? 127 : (char)(*s & 0x1f);   // ^? = DEL
            s++;
        } else {
            *out++ = *s++;
        }
    }
    return out;
}

char *tgetstr(const char *id, char **area) {
    const char *f = find_field(id);
    if (f == NULL || *f != '=') return NULL;
    char *start = *area;
    char *end = decode(f + 1, start);
    *end = '\0';
    *area = end + 1;
    return start;
}

int tgetnum(const char *id) {
    const char *f = find_field(id);
    if (f == NULL || *f != '#') return -1;
    return atoi(f + 1);
}

int tgetflag(const char *id) {
    const char *f = find_field(id);
    return (f != NULL && *f == ':') ? 1 : 0;
}

int tputs(const char *str, int affcnt, int (*outc)(int)) {
    (void)affcnt;
    if (str == NULL) return 0;
    while (*str != '\0') {
        if (*str == '$' && str[1] == '<') {
            const char *e = strchr(str + 2, '>');   // 跳过 $<nn> padding 说明
            if (e != NULL) { str = e + 1; continue; }
        }
        outc((unsigned char)*str++);
    }
    return 0;
}

char *tgoto(const char *cap, int a, int b) {
    static char buf[64];
    int args[2] = { b, a };   // ncurses 兼容：第一个转换符取第二参数
    int ai = 0;
    char *o = buf;
    for (const char *s = cap; *s != '\0' && o < buf + sizeof(buf) - 12; s++) {
        if (*s != '%') { *o++ = *s; continue; }
        s++;
        switch (*s) {
        case '%': *o++ = '%'; break;
        case 'd': if (ai < 2) { o += sprintf(o, "%d", args[ai]); ai++; } break;
        case 'c': if (ai < 2) { *o++ = (char)args[ai]; ai++; } break;
        case 'i': args[0]++; args[1]++; break;
        case '+': s++; if (*s != '\0' && ai < 2) { *o++ = (char)(args[ai] + *s); ai++; } break;
        case '\'': s++; if (*s != '\0') { int v = (unsigned char)*s; if (s[1] == '\'') s++; if (ai < 2) { *o++ = (char)v; ai++; } } break;
        default: break;   // %2/%3/%r 等本条目集未用
        }
    }
    *o = '\0';
    return buf;
}
