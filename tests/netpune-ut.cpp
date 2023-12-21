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
#include "rmunit.h"
#include "netpune.h"

using namespace netpune;

const std::string echo_tcp_server_name{ "tcpbin.com" };
const std::string echo_tcp_server_numeric{ "45.79.112.203" };
const std::string echo_tcp_server_port{ "4242" };
const std::string echo_tcp_server_url{ "tcpbin.com:4242" };
const std::string echo_tcp_server_numeric_url{ "45.79.112.203:4242" };

const std::string echo_tls_server_name{ "tcpbin.com" };
const std::string echo_tls_server_numeric{ "45.79.112.203" };
const std::string echo_tls_server_port{ "4243" };
const std::string echo_tls_server_url{ "tcpbin.com:4243" };
const std::string echo_tls_server_numeric_url{ "45.79.112.203:4243" };

const std::string bogus_name("total_bogus_host_url");
const std::string bogus_port("10101");
const std::string bogus_url("total_bogus_host_url:10101");

TEST_CASE("Test status_t class", "[status_t]")
{
	using status_t = status_base_t<int>;

	SECTION("Test status_t default constructor")
	{
		status_t status;
		REQUIRE(status.ok());
		REQUIRE(!status.nok());
		REQUIRE(!status.would_block());
		REQUIRE(status.code() == 0);
	}
	SECTION("Test status_t explicit constructor")
	{
		status_t status(WSAEWOULDBLOCK);
		REQUIRE(!status.ok());
		REQUIRE(status.nok());
		REQUIRE(status.would_block());
		REQUIRE(status.code() == WSAEWOULDBLOCK);
	}
}

TEST_CASE("Test functions", "[functions]")
{
	SECTION("Test ip::local_host_name() function")
	{
		std::string name;
		tcp::status_t status = ip::local_host_name(name);
		REQUIRE(status.ok());
		REQUIRE(!status.nok());
		REQUIRE(!status.would_block());
		REQUIRE(name.length() > 0);
	}
	SECTION("Test ip::name_resolution() name and port")
	{
		ip::address_list_t address_list;
		tcp::status_t status = ip::address_resolution(echo_tcp_server_name, echo_tcp_server_port, address_list);
		REQUIRE(status.ok());
		REQUIRE(!status.nok());
		REQUIRE(!status.would_block());
		REQUIRE(address_list.size() > 0);
	}
	SECTION("Test ip::name_resolution() name:port")
	{
		ip::address_list_t address_list;
		tcp::status_t status = ip::address_resolution(echo_tcp_server_url, address_list);
		REQUIRE(status.ok());
		REQUIRE(!status.nok());
		REQUIRE(!status.would_block());
		REQUIRE(address_list.size() > 0);
	}
	SECTION("Test ipname_resolution() numeric and port")
	{
		ip::address_list_t address_list;
		tcp::status_t status = ip::address_resolution(echo_tcp_server_numeric, echo_tcp_server_port, address_list);
		REQUIRE(status.ok());
		REQUIRE(!status.nok());
		REQUIRE(!status.would_block());
		REQUIRE(address_list.size() > 0);
	}
	SECTION("Test ipname_resolution() numeric:port")
	{
		ip::address_list_t address_list;
		tcp::status_t status = ip::address_resolution(echo_tcp_server_numeric_url, address_list);
		REQUIRE(status.ok());
		REQUIRE(!status.nok());
		REQUIRE(!status.would_block());
		REQUIRE(address_list.size() > 0);
	}
	SECTION("Test ipname_resolution() failure")
	{
		ip::address_list_t address_list;
		tcp::status_t status = ip::address_resolution(bogus_name, bogus_port, address_list);
		REQUIRE(!status.ok());
		REQUIRE(status.nok());
		REQUIRE(!status.would_block());
		REQUIRE(address_list.empty());
	}
}


