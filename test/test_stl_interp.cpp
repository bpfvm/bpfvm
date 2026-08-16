// Tree-walking interpreter on bpfvm — bootstrap probe step 1.
//
// 目标：在 bpfvm 上用 C++ 实现一个完整的小语言解释器（词法 -> 递归下降 parser
// -> AST -> 求值），验证编译器前端内核在 BPF 上能跑通，并暴露 C++/libc++/VM 侧
// 的剩余缺口。这是朝"自举"目标走的第一步：环境若能解释一个有变量/算术/控制流
// 的小语言，就具备写更大编译器的 C++ 基础。
//
// 语法：
//   program := stmt*
//   stmt    := assign ';' | print ';' | if | while | block
//   assign  := ID '=' expr
//   print   := 'print' expr
//   if      := 'if' expr stmt ('else' stmt)?
//   while   := 'while' expr stmt
//   block   := '{' stmt* '}'
//   expr    := cmp
//   cmp     := add (('<'|'>'|'=='|'!='|'<='|'>=') add)?
//   add     := mul (('+'|'-') mul)*
//   mul     := unary (('*'|'/'|'%') unary)*
//   unary   := '-'? primary
//   primary := NUM | ID | '(' expr ')'
//
// 用 std::string/vector/unordered_map/unique_ptr + printf（musl）。不依赖未支持
// 的头（regex/iostream/thread）。byval 传 unique_ptr/AST 节点已被 lowerAggregateParams
// 路径 A（原 stripByval）解锁。

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <cstdio>

// ============================== Lexer ==============================
struct Token {
    enum Kind {
        NUM, ID,
        PLUS, MINUS, STAR, SLASH, PCT,
        LP, RP, LC, RC,
        EQ, EQEQ, NEQ, LT, GT, LE, GE,
        SEMI,
        KW_IF, KW_ELSE, KW_WHILE, KW_PRINT,
        END
    } kind;
    long num = 0;
    std::string id;
};

static std::vector<Token> g_tok;
static size_t g_pos = 0;

static void tokenize(const char *s, std::vector<Token> &out) {
    out.clear();
    while (*s) {
        char c = *s;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') { ++s; continue; }
        if (c >= '0' && c <= '9') {
            long v = 0;
            while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); ++s; }
            out.push_back({Token::NUM, v, ""});
            continue;
        }
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
            std::string id;
            while ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
                   (*s >= '0' && *s <= '9') || *s == '_') { id += *s; ++s; }
            Token::Kind k = Token::ID;
            if (id == "if") k = Token::KW_IF;
            else if (id == "else") k = Token::KW_ELSE;
            else if (id == "while") k = Token::KW_WHILE;
            else if (id == "print") k = Token::KW_PRINT;
            out.push_back({k, 0, id});
            continue;
        }
        ++s;
        switch (c) {
            case '+': out.push_back({Token::PLUS}); break;
            case '-': out.push_back({Token::MINUS}); break;
            case '*': out.push_back({Token::STAR}); break;
            case '/': out.push_back({Token::SLASH}); break;
            case '%': out.push_back({Token::PCT}); break;
            case '(': out.push_back({Token::LP}); break;
            case ')': out.push_back({Token::RP}); break;
            case '{': out.push_back({Token::LC}); break;
            case '}': out.push_back({Token::RC}); break;
            case ';': out.push_back({Token::SEMI}); break;
            case '=':
                if (*s == '=') { ++s; out.push_back({Token::EQEQ}); }
                else out.push_back({Token::EQ});
                break;
            case '!':
                if (*s == '=') { ++s; out.push_back({Token::NEQ}); }
                break;
            case '<':
                if (*s == '=') { ++s; out.push_back({Token::LE}); }
                else out.push_back({Token::LT});
                break;
            case '>':
                if (*s == '=') { ++s; out.push_back({Token::GE}); }
                else out.push_back({Token::GT});
                break;
            default: break;
        }
    }
    out.push_back({Token::END});
}

// ============================== AST ==============================
struct Expr {
    enum Kind { NUM, VAR, BINOP, UNARY } kind;
    long num = 0;
    std::string id;
    int op = 0;
    std::unique_ptr<Expr> left, right;
};
using ExprPtr = std::unique_ptr<Expr>;

struct Stmt {
    enum Kind { ASSIGN, PRINT, IF, WHILE, BLOCK } kind;
    std::string id;
    ExprPtr expr;
    std::unique_ptr<Stmt> thenS, elseS;   // IF: then/else;  WHILE: body
    std::vector<std::unique_ptr<Stmt>> body;  // BLOCK
};
using StmtPtr = std::unique_ptr<Stmt>;

// ============================== Parser（递归下降）==============================
static const Token &peek() { return g_tok[g_pos]; }
static const Token &advance() { return g_tok[g_pos++]; }

static ExprPtr parse_expr();

static ExprPtr mk_num(long v) {
    auto e = std::make_unique<Expr>(); e->kind = Expr::NUM; e->num = v; return e;
}
static ExprPtr mk_var(std::string id) {
    auto e = std::make_unique<Expr>(); e->kind = Expr::VAR; e->id = id; return e;
}
static ExprPtr mk_unary(int op, ExprPtr sub) {
    auto e = std::make_unique<Expr>(); e->kind = Expr::UNARY; e->op = op; e->left = std::move(sub); return e;
}
static ExprPtr mk_binop(int op, ExprPtr l, ExprPtr r) {
    auto e = std::make_unique<Expr>(); e->kind = Expr::BINOP; e->op = op;
    e->left = std::move(l); e->right = std::move(r); return e;
}

static ExprPtr parse_primary() {
    const Token &t = peek();
    if (t.kind == Token::NUM) { advance(); return mk_num(t.num); }
    if (t.kind == Token::ID)  { advance(); return mk_var(t.id); }
    if (t.kind == Token::LP)  { advance(); auto e = parse_expr(); if (peek().kind == Token::RP) advance(); return e; }
    return mk_num(0);
}

static ExprPtr parse_unary() {
    if (peek().kind == Token::MINUS) { advance(); return mk_unary(Token::MINUS, parse_unary()); }
    return parse_primary();
}

static ExprPtr parse_mul() {
    ExprPtr l = parse_unary();
    while (peek().kind == Token::STAR || peek().kind == Token::SLASH || peek().kind == Token::PCT) {
        int op = peek().kind; advance();
        l = mk_binop(op, std::move(l), parse_unary());
    }
    return l;
}

static ExprPtr parse_add() {
    ExprPtr l = parse_mul();
    while (peek().kind == Token::PLUS || peek().kind == Token::MINUS) {
        int op = peek().kind; advance();
        l = mk_binop(op, std::move(l), parse_mul());
    }
    return l;
}

static ExprPtr parse_cmp() {
    ExprPtr l = parse_add();
    int k = peek().kind;
    if (k == Token::LT || k == Token::GT || k == Token::LE || k == Token::GE ||
        k == Token::EQEQ || k == Token::NEQ) {
        advance();
        l = mk_binop(k, std::move(l), parse_add());
    }
    return l;
}

static ExprPtr parse_expr() { return parse_cmp(); }

static StmtPtr parse_stmt();

static StmtPtr parse_block() {  // '{' 已消费
    auto s = std::make_unique<Stmt>(); s->kind = Stmt::BLOCK;
    while (peek().kind != Token::RC && peek().kind != Token::END)
        s->body.push_back(parse_stmt());
    if (peek().kind == Token::RC) advance();
    return s;
}

static StmtPtr parse_stmt() {
    const Token &t = peek();
    auto s = std::make_unique<Stmt>();
    if (t.kind == Token::LC) { advance(); return parse_block(); }
    if (t.kind == Token::KW_IF) {
        advance(); s->kind = Stmt::IF; s->expr = parse_expr();
        s->thenS = parse_stmt();
        if (peek().kind == Token::KW_ELSE) { advance(); s->elseS = parse_stmt(); }
        return s;
    }
    if (t.kind == Token::KW_WHILE) {
        advance(); s->kind = Stmt::WHILE; s->expr = parse_expr();
        s->thenS = parse_stmt();  // 循环体复用 thenS
        return s;
    }
    if (t.kind == Token::KW_PRINT) {
        advance(); s->kind = Stmt::PRINT; s->expr = parse_expr();
        if (peek().kind == Token::SEMI) advance();
        return s;
    }
    if (t.kind == Token::ID) {
        s->kind = Stmt::ASSIGN; s->id = t.id; advance();
        if (peek().kind == Token::EQ) advance();
        s->expr = parse_expr();
        if (peek().kind == Token::SEMI) advance();
        return s;
    }
    advance();  // 出错兜底：跳过
    s->kind = Stmt::PRINT; s->expr = mk_num(0);
    return s;
}

// ============================== Eval（tree-walking）==============================
static std::unordered_map<std::string, long> g_env;

static long eval(const Expr &e) {
    switch (e.kind) {
        case Expr::NUM: return e.num;
        case Expr::VAR: {
            auto it = g_env.find(e.id);
            return it == g_env.end() ? 0 : it->second;
        }
        case Expr::UNARY: return -eval(*e.left);
        case Expr::BINOP: {
            long l = eval(*e.left), r = eval(*e.right);
            switch (e.op) {
                case Token::PLUS:  return l + r;
                case Token::MINUS: return l - r;
                case Token::STAR:  return l * r;
                case Token::SLASH: return r ? l / r : 0;
                case Token::PCT:   return r ? l % r : 0;
                case Token::LT:    return l < r;
                case Token::GT:    return l > r;
                case Token::LE:    return l <= r;
                case Token::GE:    return l >= r;
                case Token::EQEQ:  return l == r;
                case Token::NEQ:   return l != r;
            }
        }
    }
    return 0;
}

static void exec(const Stmt &s) {
    switch (s.kind) {
        case Stmt::ASSIGN: g_env[s.id] = eval(*s.expr); break;
        case Stmt::PRINT:  printf("%ld\n", eval(*s.expr)); break;
        case Stmt::IF:
            if (eval(*s.expr)) { if (s.thenS) exec(*s.thenS); }
            else               { if (s.elseS) exec(*s.elseS); }
            break;
        case Stmt::WHILE:
            while (eval(*s.expr)) { if (s.thenS) exec(*s.thenS); }
            break;
        case Stmt::BLOCK:
            for (const auto &st : s.body) exec(*st);
            break;
    }
}

// 跑一段脚本，返回变量 var 的最终值。
static long run(const char *src, const char *var) {
    g_tok.clear(); g_pos = 0; g_env.clear();
    tokenize(src, g_tok);
    while (peek().kind != Token::END) {
        StmtPtr s = parse_stmt();
        exec(*s);
    }
    auto it = g_env.find(var);
    return it == g_env.end() ? 0 : it->second;
}

int main() {
    int fails = 0;
    auto check = [&](const char *src, const char *var, long expect) {
        long got = run(src, var);
        if (got != expect) {
            printf("FAIL [%s] %s=%ld expect %ld\n", src, var, got, expect);
            ++fails;
        }
    };

    check("x = 1 + 2 * 3;",            "x", 7);    // 优先级：*
    check("x = (1 + 2) * 3;",          "x", 9);    // 括号
    check("x = 2 * 3 + 4 * 5;",        "x", 26);   // 6 + 20
    check("a = -3 + 5;",               "a", 2);    // 一元负
    check("x = 7; y = 2; z = x % y;",  "z", 1);    // 模
    check("x = 5; if x > 3 { x = 10; } else { x = 0; }", "x", 10);  // if true
    check("x = 1; if x > 3 { x = 10; } else { x = 0; }", "x", 0);   // if false -> else
    check("i = 1; s = 0; while i <= 10 { s = s + i; i = i + 1; }", "s", 55);  // 1..10 求和
    check("n = 5; f = 1; while n > 1 { f = f * n; n = n - 1; }", "f", 120);   // 5! 阶乘
    check("a = 0; b = 0; while a < 5 { b = b + a * a; a = a + 1; }", "b", 30); // 0+1+4+9+16
    check("x = 10; y = 3; if x % y == 1 { r = 100; } else { r = 200; }", "r", 100); // 嵌套 cmp

    printf("stl_interp: %d cases, %s\n", 11, fails ? "FAIL" : "all ok");
    return fails ? 1 : 0;
}
