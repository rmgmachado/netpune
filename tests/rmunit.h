/*****************************************************************************\
*  Copyright (c) 2023 Ricardo Machado, Sydney, Australia All rights reserved.
*
*  MIT License
*
*  Permission is hereby granted, free of charge, to any person obtaining a copy
*  of this software and associated documentation files (the "Software"), to
*  deal in the Software without restriction, including without limitation the
*  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
*  sell copies of the Software, and to permit persons to whom the Software is
*  furnished to do so, subject to the following conditions:
*
*  The above copyright notice and this permission notice shall be included in
*  all copies or substantial portions of the Software.
*
*  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
*  IN THE SOFTWARE.
*
*  You should have received a copy of the MIT License along with this program.
*  If not, see https://opensource.org/licenses/MIT.
\*****************************************************************************/
#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <utility>
#include <algorithm>

namespace rmunit {

   class xp_unit_test;

   class xp_test_suite
   {
      unsigned int passed_;
      unsigned int failed_;
      std::string name_;
      std::vector<std::pair<xp_unit_test*, std::string>> tests_;

   public:
      xp_test_suite() noexcept
         : passed_(0)
         , failed_(0)
         , tests_()
         , name_("Unit Tests")
      {}

      ~xp_test_suite() = default;

      xp_test_suite(const xp_test_suite&) = delete;
      xp_test_suite(xp_test_suite&&) = delete;

      xp_test_suite& operator=(const xp_test_suite&) = delete;
      xp_test_suite& operator=(xp_test_suite&&) = delete;

      static xp_test_suite& get() noexcept
      {
         static rmunit::xp_test_suite instance;
         return instance;
      }

      int execute(const std::string& title, bool verbose = false) noexcept;

      void add_test_unit(xp_unit_test* test, const std::string& name) noexcept
      {
         if (test)
         {
            tests_.push_back(std::make_pair(test, name));
         }
      }

   };

   class xp_unit_test
   {
      std::string name_;
      std::string tag_;
      unsigned int passed_;
      unsigned int failed_;
      bool verbose_;

   public:
      xp_unit_test() = delete;
      virtual ~xp_unit_test() {}

      xp_unit_test(const std::string& name, const std::string& tag) noexcept
         : name_(name)
         , tag_(tag)
         , passed_(0)
         , failed_(0)
         , verbose_(false)
      {
         xp_test_suite::get().add_test_unit(this, name_);
      }

      xp_unit_test(const xp_unit_test&) = default;
      xp_unit_test(xp_unit_test&&) = default;
      xp_unit_test& operator=(const xp_unit_test&) = default;
      xp_unit_test& operator=(xp_unit_test&&) = default;

      void section(const std::string& name) const noexcept
      {
         if (verbose_)
         {
            std::cout << "  SECTION: " << name << "\n";
         }
      }

      void require(bool expression, const char* condition, const std::string& source = "", int line = 0) noexcept
      {
         const char* result = expression ? "  PASS " : "  FAIL ";
         if (expression)
         {
            ++passed_;
         }
         else
         {
            ++failed_;
         }
         if (verbose_ || !expression)
         {
            std::cout << result << source << " (" << line <<"): " << condition << "\n";
         }
      }

      virtual void execute()
      {}

      unsigned int passed() const noexcept
      {
         return passed_;
      }

      unsigned int failed() const noexcept
      {
         return failed_;
      }

      void verbose(bool flag) noexcept
      {
         verbose_ = flag;
      }
   };

   inline int xp_test_suite::execute(const std::string& title, bool verbose) noexcept
   {
      std::cout << "TEST SUIT: " << title << "\n";
      std::cout << "--------------------------------------------------------------\n";
      for (auto& test : tests_)
      {
         test.first->verbose(verbose);
         std::cout << "TEST CASE: " << test.second << "\n";
         test.first->execute();
         unsigned int passed = test.first->passed();
         unsigned int failed = test.first->failed();
         passed_ += passed;
         failed_ += failed;
         if (verbose)
         {
            std::cout << "  TOTAL " << (passed + failed) << " Passed: " << passed << " Failed: " << failed << "\n";
         }
      }
      std::cout << "--------------------------------------------------------------\n";
      std::cout << "TOTAL: " << (passed_ + failed_) << " PASSED: " << passed_ << " FAILED: " << failed_ << "\n";
      return failed_;
   }

   inline int xpunit_main(int argc, char** argv, const char* title)
   {
      bool verbose = false;
      for (int i = 1; i < argc; ++i)
      {
         char* str = argv[i];
         if (str && (*str == '-' || *str == '/'))
         {
            ++str;
            if (*str == 'v' || *str == 'V')
               verbose = true;
            else
               std::cerr << "Error: invalid or unknown argument " << argv[i] << "\n";
         }
         else
            std::cerr << "Error: invalid or unknown argument " << argv[i] << "\n";
      }
      return xp_test_suite::get().execute(title, verbose);
   }
} // namespace xpunit

#define RM_CONCAT(a, b) RM_CONCAT_INNER(a, b)
#define RM_CONCAT_INNER(a, b) a ## b
#define RM_UNIQUE_NAME(base) RM_CONCAT(base, __COUNTER__)

#define TEST_CASE_INTERNAL(name, tag, TEST_CASE_NAME) \
   namespace { \
   class TEST_CASE_NAME : public rmunit::xp_unit_test \
   {\
   public:\
      TEST_CASE_NAME() : rmunit::xp_unit_test(name, tag) {} \
      virtual void execute(); \
   };\
   static TEST_CASE_NAME RM_UNIQUE_NAME(unit_test_); \
   } \
   void TEST_CASE_NAME::execute()

#define TEST_CASE(name, tag)  TEST_CASE_INTERNAL(name, tag, RM_UNIQUE_NAME(xp_unit_test_))

#define SECTION(description)  section(description);

#define REQUIRE(expression)   require(expression, #expression, __FILE__, __LINE__)

#define XPUNIT_MAIN(title) \
    int main(int argc, char** argv) \
    { \
        return rmunit::xpunit_main(argc, argv, title); \
    }
