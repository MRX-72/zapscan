#include "test_harness.hpp"

TEST(version_comes_from_the_build) {
    const std::string version = ZAPSCAN_VERSION;
    EXPECT_FALSE(version.empty());
    EXPECT_TRUE(version.find_first_not_of("0123456789.") == std::string::npos);
    EXPECT_TRUE(version.find('.') != std::string::npos);
    EXPECT_TRUE(version.back() != '.');
}

int main() {
    return test::run_all();
}
