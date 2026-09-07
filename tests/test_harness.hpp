#pragma once

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace test {

struct Case {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

inline int& failures() {
    static int count = 0;
    return count;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

inline void fail(const char* file, int line, const std::string& msg) {
    failures()++;
    std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, msg.c_str());
}

inline int run_all() {
    for (auto& c : registry()) {
        int before = failures();
        std::fprintf(stderr, "ok - %s\n", c.name);
        c.fn();
        if (failures() > before) {
            std::fprintf(stderr, "not ok - %s\n", c.name);
        }
    }
    if (failures() == 0) {
        std::fprintf(stderr, "PASS (%zu cases)\n", registry().size());
        return 0;
    }
    std::fprintf(stderr, "FAIL (%d assertions)\n", failures());
    return 1;
}

}  // namespace test

#define TEST(name)                                                     \
    static void test_##name();                                         \
    static test::Registrar reg_##name(#name, test_##name);             \
    static void test_##name()

#define EXPECT_TRUE(expr)                                                     \
    do {                                                                      \
        if (!(expr)) {                                                        \
            test::fail(__FILE__, __LINE__, "expected true: " #expr);          \
        }                                                                     \
    } while (0)

#define EXPECT_FALSE(expr)                                                    \
    do {                                                                      \
        if ((expr)) {                                                         \
            test::fail(__FILE__, __LINE__, "expected false: " #expr);         \
        }                                                                     \
    } while (0)

#define EXPECT_EQ(a, b)                                                       \
    do {                                                                      \
        auto va_ = (a);                                                       \
        auto vb_ = (b);                                                       \
        if (!(va_ == vb_)) {                                                  \
            std::ostringstream os_;                                           \
            os_ << "expected equal: " #a " == " #b;                           \
            test::fail(__FILE__, __LINE__, os_.str());                        \
        }                                                                     \
    } while (0)

#define EXPECT_NE(a, b)                                                       \
    do {                                                                      \
        auto va_ = (a);                                                       \
        auto vb_ = (b);                                                       \
        if (!(va_ != vb_)) {                                                  \
            std::ostringstream os_;                                           \
            os_ << "expected not equal: " #a " != " #b;                       \
            test::fail(__FILE__, __LINE__, os_.str());                        \
        }                                                                     \
    } while (0)