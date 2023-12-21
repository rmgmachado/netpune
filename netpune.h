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

#include <cstdint>
#include <string>
#include <array>
#include <vector>
#include <optional>
#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>

/*****************************************************************************\
*
*  Windows specific definitionss
*
\*****************************************************************************/
#if defined(_MSC_VER)
   #define NETPUNE_WIN32

   #include <winsock2.h>
   #include <ws2tcpip.h>

   #include "wepoll.h"

   #define WSAEAGAIN WSAEWOULDBLOCK
   constexpr HANDLE INVALID_EPOLL_HANDLE = nullptr;

   // link with Ws2_32.lib
   #pragma comment (lib, "Ws2_32.lib")
#endif

/*****************************************************************************\
*
*  Linux specific definitions
*
\*****************************************************************************/
#if defined(__GNUC__)
   #define NETPUNE_LINUX

   #include <sys/types.h>
   #include <sys/socket.h>
   #include <sys/ioctl.h>
   #include <sys/epoll.h>
   #include <netdb.h>
   #include <unistd.h>
   #include <fcntl.h>
   #include <poll.h>
   #include <errno.h>
   #include <string.h>

   using SOCKET = int;
   using HANDLE = int;
   using WSAPOLLFD = struct pollfd;
   using LPWSAPOLLFD = struct pollfd*;
   using ADDRINFOA = struct addrinfo;
   using PADDRINFOA = struct addrinfo*;

   inline int WSAGetLastError() noexcept { return errno; }
   inline int closesocket(SOCKET fd) noexcept { return ::close(fd); }
   inline int ioctlsocket(SOCKET fd, long cmd, u_long* argp) noexcept { return ::ioctl(fd, cmd, argp); }
   inline int WSAPoll(LPWSAPOLLFD fdArray, nfds_t nfds, int timeout) { return ::poll(fdArray, nfds, timeout); }
   inline void ZeroMemory(void* ptr, size_t size) { memset(ptr, '\0', size); }
   inline int epoll_close(HANDLE ephnd) { return close(ephnd); }

   constexpr int INVALID_SOCKET = -1;
   constexpr int SOCKET_ERROR = -1;
   constexpr HANDLE INVALID_EPOLL_HANDLE = -1;

   #define WSAEWOULDBLOCK  EWOULDBLOCK
   #define WSAECONNREFUSED ECONNREFUSED
   #define WSAEHOSTUNREACH ENETUNREACH 
   #define WSAEAGAIN       EAGAIN
   #define WSAEINVAL       EINVAL
   #define WSAENOTSOCK     ENOTSOCK

   #define SD_SEND      SHUT_WR
   #define SD_RECEIVE   SHUT_RD
   #define SD_BOTH      SHUT_RDWR

   struct WSADATA { int wsadata_{}; };
   void WSAStartup(unsigned, WSADATA*) {}
   void WSACleanup() {}
#endif

namespace netpune {

   constexpr unsigned int KBytes(unsigned int n) noexcept { return n * 1024; }
   constexpr unsigned int MBytes(unsigned int n) noexcept { return n * 1024 * 1024; }

   // socket_recv_buffer_size controls the size of a buffer in the stack
   // when socket_base_t::recv(std::string&) is called. Small values will 
   // require more calls to ::recv to receive all data in sockets buffer
   constexpr size_t SOCKET_RECV_SIZE = KBytes(16);

   // define default listen() backlog size
   constexpr int SOCKET_LISTEN_BACKLOG = 512;

   // define how long epoll should wait in milliseconds before returning
   constexpr int SOCKET_EPOLL_WAIT_TIMEOUT_MS = 10;

   constexpr size_t MAX_ERROR_STRING_SIZE = 256;

   // Define the ContiguousContainer concept
   template<typename T>
   concept ContiguousContainer = requires(T t) {
      { t.data() } -> std::same_as<typename std::remove_pointer<decltype(t.data())>::type*>;
   };

   namespace bsd {

      /**********************************************************************\
      * 
      *  class wrapping BSD socket functionality
      *  this class allow for wrapping of all socket functions to allow for
      *  mocking and unit testing.
      * 
      *  All functions return 0 on success or an error code returned by
      *  WSAGetLastError()
      * 
      \**********************************************************************/
      struct socket_t
      {
         using native_handle = SOCKET;
         native_handle handle{ INVALID_SOCKET };

         static int error_check(int ret) noexcept
         {
            return (ret == 0) ? 0 : socket_t::WSAGetLastError();
         }

         socket_t(const socket_t& other) noexcept
            : handle{ other.handle }
         {}

         int create(int family) noexcept
         {
            handle = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
            return (handle != INVALID_SOCKET) ? 0 : socket_t::WSAGetLastError();
         }

         int close() noexcept
         {
            int ret = ::closesocket(handle);
            handle = (ret == 0) ? INVALID_SOCKET : handle;
            return error_check(ret);
         }

         int shutdown(int how) noexcept
         {
            return error_check(::shutdown(handle, how));
         }

         int connect(const sockaddr* name, int namelen) noexcept
         {
            return error_check(::connect(handle, name, namelen));
         }

         int bind(const sockaddr* name, int namelen) noexcept
         {
            return error_check(::bind(handle, name, namelen));
         }

         int listen(int backlog) noexcept
         {
            return error_check(::listen(handle, backlog));
         }

         int accept(native_handle& client, sockaddr* name, socklen_t* namelen) noexcept
         {
            client = ::accept(handle, name, namelen);
            return client != INVALID_SOCKET ? 0 : socket_t::WSAGetLastError();
         }

         int send(const char* buffer, size_t length, size_t& bytes_sent) noexcept
         {
            int ret = ::send(handle, buffer, static_cast<int>(length), 0);
            bytes_sent = (ret != SOCKET_ERROR) ? ret : 0;
            return (ret != SOCKET_ERROR) ? 0 : socket_t::WSAGetLastError();
         }

         int recv(char* buffer, size_t length, size_t& bytes_received) noexcept
         {
            int ret = ::recv(handle, buffer, static_cast<int>(length), 0);
            bytes_received = (ret != SOCKET_ERROR) ? ret : 0;
            return (ret != SOCKET_ERROR) ? 0 : socket_t::WSAGetLastError();
         }

         int poll(LPWSAPOLLFD fd_array, ULONG fds, int& active, int timeout_ms) noexcept
         {
            int ret = ::WSAPoll(fd_array, fds, timeout_ms);
            active = (ret != SOCKET_ERROR) ? ret : 0;
            return (ret != SOCKET_ERROR) ? 0 : socket_t::WSAGetLastError();
         }

         int ioctlsocket(long cmd, u_long* argp) noexcept
         {
            return error_check(::ioctlsocket(handle, cmd, argp));
         }

         int setsockopt(int level, int optname, const char* optval, socklen_t optlen) const noexcept
         {
            return error_check(::setsockopt(handle, level, optname, optval, optlen));
         }

         int getsockopt(int level, int optname, char* optval, socklen_t* optlen) const noexcept
         {
            return error_check(::getsockopt(handle, level, optname, optval, optlen));
         }

         static int getnameinfo(const SOCKADDR* addr, socklen_t addr_len, char* host, unsigned host_len, char* port, unsigned port_len, int flags) noexcept
         {
            return (::getnameinfo(addr, addr_len, host, host_len, port, port_len, flags) == 0) ? 0 : socket_t::WSAGetLastError();
         }

         static int gethostname(char* name, int name_len) noexcept
         {
            return error_check(::gethostname(name, name_len));
         }

         static int getaddrinfo(const char* host, const char* port, const ADDRINFOA* hints, PADDRINFOA* results) noexcept
         {
            return ::getaddrinfo(host, port, hints, results);
         }

         static void freeaddrinfo(PADDRINFOA info) noexcept
         {
            ::freeaddrinfo(info);
         }

         static int WSAGetLastError() noexcept
         {
            return ::WSAGetLastError();
         }
      };

   }; // namespace bsd

   /*****************************************************************************\
   *
   *  class status_base_t
   *
   \*****************************************************************************/
   template <typename ErrT, ErrT OK = 0>
   class status_base_t
   {
      ErrT code_{ OK };

   public:
      using value_type = ErrT;

      status_base_t() = default;
      ~status_base_t() = default;
      status_base_t(const status_base_t&) noexcept = default;
      status_base_t(status_base_t&&) noexcept = default;
      status_base_t& operator=(const status_base_t&) noexcept = default;
      status_base_t& operator=(status_base_t&&) noexcept = default;

      explicit status_base_t(ErrT code) noexcept
         : code_{ code }
      {}

      friend void swap(status_base_t& lhs, status_base_t& rhs) noexcept
      {
         std::swap(lhs.code_, rhs.code_);
      }

      bool operator==(const status_base_t& other) const
      {
         return code_ == other.code_;
      }

      constexpr bool ok() const noexcept
      {
         return code_ == OK;
      }

      constexpr bool nok() const noexcept
      {
         return code_ != OK;
      }

      constexpr bool would_block() const noexcept
      {
         return code_ == WSAEWOULDBLOCK || code_ == WSAEAGAIN;
      }

      value_type code() const noexcept
      {
         return code_;
      }

      void code(value_type n) noexcept
      {
         code_ = n;
      };

      std::string reason() const noexcept
      {
         if (code_ != OK)
         {
            std::array<char,MAX_ERROR_STRING_SIZE> text;
            if (strerror_s(text.data(), text.size(), code_) == 0)
            {
               return std::string(text.data());
            }
         }
         return std::string();
      }

   }; //class status_base_t

   namespace tcp {

      using status_t = status_base_t<int>;
      inline status_t last_error() noexcept { return status_t(bsd::socket_t::WSAGetLastError()); }

   } // namespace tcp

   namespace ip {

      /***********************************************************************\
      *
      *  class address_t
      *
      \***********************************************************************/
      class address_t
      {
         sockaddr addr_{};
         socklen_t len_{ 0 };

      public:
         address_t() = default;
         ~address_t() = default;
         address_t(const address_t&) = default;
         address_t(address_t&&) = default;
         address_t& operator=(const address_t&) = default;
         address_t& operator=(address_t&&) = default;

         address_t(const sockaddr* addr, socklen_t len) noexcept
            : addr_{ addr ? *addr : sockaddr{} }
            , len_{ len }
         {}

         address_t(const sockaddr& addr, socklen_t len) noexcept
            : addr_{ addr }
            , len_{ len }
         {}

         friend void swap(address_t& lhs, address_t& rhs) noexcept
         {
            std::swap(lhs.addr_, rhs.addr_);
            std::swap(lhs.len_, rhs.len_);
         }

         const sockaddr* address() const noexcept
         {
            return &addr_;
         }

         socklen_t length() const noexcept
         {
            return len_;
         }

         int family() const noexcept
         {
            return addr_.sa_family;
         }
      }; // class ipaddress_t

      /***********************************************************************\
      *
      *  Retrieve the peer name from ipaddress_t in the format "host:port".
      *  Returns an empty string if the host name cannot be retrieved
      *
      \***********************************************************************/
      inline tcp::status_t peer_name(const address_t& address, std::string& name) noexcept
      {
         std::array<char, NI_MAXHOST> host = {};
         std::array<char, NI_MAXSERV> port = {};
         int ret{ 0 };
         if (ret = bsd::socket_t::getnameinfo(address.address(), address.length(), host.data(), (socklen_t)host.size(), port.data(), (socklen_t)port.size(), (NI_NUMERICHOST | NI_NUMERICSERV)); ret == 0)
         {
            name = std::string(host.data()) + std::string(":") + std::string(port.data());
            return tcp::status_t();
         }
         return tcp::status_t(ret);
      }

      /*****************************************************************************\
      *
      *  local_host_name()
      *  Retrieve the name of the local host. Returns an empty string if the local
      *  host name cannot be retrieved
      *
      \*****************************************************************************/
      inline tcp::status_t local_host_name(std::string& host) noexcept
      {
         constexpr const int HN_MAX_HOSTNAME = 256;
         std::array<char, HN_MAX_HOSTNAME> name = {};
         if (bsd::socket_t::gethostname(&name[0], (int)name.size()) == 0)
         {
            host = std::string(name.data());
            return tcp::status_t();
         }
         return tcp::last_error();
      }

      using address_list_t = std::vector<address_t>;

      enum class resolution_type_t : int { normal = 0, passive = AI_PASSIVE };

      inline tcp::status_t address_resolution(const std::string& host, const std::string& port, address_list_t& address_list, resolution_type_t type = resolution_type_t::normal) noexcept
      {
         PADDRINFOA addr{ nullptr };
         PADDRINFOA ptr{ nullptr };
         ADDRINFOA hints;
         ZeroMemory(&hints, sizeof(hints));
         hints.ai_flags = (int)type;
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_STREAM;
         hints.ai_protocol = IPPROTO_TCP;
         int retval = bsd::socket_t::getaddrinfo(host.c_str(), port.c_str(), &hints, &addr);
         if (retval == 0)
         {
            address_list.clear();
            ptr = addr;
            while (ptr != nullptr)
            {
               if (ptr->ai_addr != nullptr && ptr->ai_addrlen > 0)
               {
                  address_list.emplace_back(address_t(ptr->ai_addr, (int)ptr->ai_addrlen));
               }
               ptr = ptr->ai_next;
            }
         }
         bsd::socket_t::freeaddrinfo(addr);
         return tcp::status_t(retval);
      }

      // resolve IP name and port in the format hostname:port
      inline tcp::status_t address_resolution(const std::string& host_and_port, address_list_t& address_list, resolution_type_t type = resolution_type_t::normal) noexcept
      {
         auto separator_pos = host_and_port.find_first_of(':');
         if (separator_pos != std::string::npos)
         {
            return address_resolution(host_and_port.substr(0, separator_pos), host_and_port.substr(separator_pos + 1), address_list, type);
         }
         return tcp::status_t(WSAEINVAL);
      }

   } // namespace ip

   namespace tcp {

      using uid_t = uint64_t;
      
      using wait_timeout_t = int;
      constexpr wait_timeout_t SOCKET_WAIT_FOREVER = -1L;
      constexpr wait_timeout_t SOCKET_WAIT_NEVER = 0L;

      enum class socket_event_t { recv_ready, send_ready, connect_ready, accept_ready, send_recv_ready };
      enum class socket_mode_t { blocking, nonblocking };
      enum class socket_close_t : int { send = SD_SEND, recv = SD_RECEIVE, both = SD_BOTH };

      template <typename T>
      class socket_base_t
      {
         T socket_;
         socket_mode_t mode_{ socket_mode_t::blocking };
         mutable uid_t uid_{ 0 };

      public:
         socket_base_t() = default;
         ~socket_base_t() = default;
         socket_base_t(const socket_base_t&) = default;
         socket_base_t& operator=(const socket_base_t&) = default;

         explicit socket_base_t(const T& socket, socket_mode_t mode = socket_mode_t::blocking) noexcept
            : socket_{ socket }
            , mode_{ mode }
         {}

         socket_base_t(socket_base_t&& other) noexcept
            : socket_{ other.socket_ }
            , mode_{ other.mode_ }
            , uid_{ other.uid_ }
         {
            other.socket_.handle = INVALID_SOCKET;
            other.mode_ = socket_mode_t::blocking;
            other.uid_ = 0;
         }

         socket_base_t& operator=(socket_base_t&& other) noexcept
         {
            if (this != &other)
            {
               socket_.handle = other.socket_.handle;
               mode_ = other.mode_;
               uid_ = other.uid_;
               other.socket_.handle = INVALID_SOCKET;
               other.mode_ = socket_mode_t::blocking;
               other.uid_ = 0;
            }
            return *this;
         }

         T::native_handle socket() const noexcept
         {
            return socket_.handle;
         }

         bool created() const noexcept
         {
            return socket_.handle != INVALID_SOCKET;
         }

         socket_mode_t get_mode() const noexcept
         {
            return mode_;
         }

         status_t set_mode(socket_mode_t mode) noexcept
         {
            u_long um = (mode == socket_mode_t::nonblocking) ? 1 : 0;
            status_t status(socket_.ioctlsocket(FIONBIO, &um));
            mode_ = status.ok() ? mode : mode_;
            return status;
         }

         uid_t uid() const noexcept
         {
            return uid_;
         }

         status_t connect(const ip::address_t& addr, socket_mode_t mode = socket_mode_t::blocking) noexcept
         {
            status_t status{ socket_.create(addr.family()) };
            if (status.ok())
            {
               if (status = socket_.connect(addr.address(), addr.length()); status.ok())
               {
                  if (status = set_mode(mode); status.ok())
                  {
                     generate_uid();
                  }
               }
            }
            if (status.nok())
            {
               socket_.close();
            }
            return status;
         }

         status_t disconnect(socket_close_t how = socket_close_t::send) noexcept
         {
            status_t status = socket_.shutdown(how);
            if (status.ok())
            {
               status = socket_.close();
            }
            return status;
         }

         status_t listen(const ip::address_t& addr, int backlog, socket_mode_t mode = socket_mode_t::blocking) noexcept
         {
            status_t status = socket_.bind(addr.address(), addr.length());
            if (status.ok())
            {
               if (status = socket_.listen(backlog); status.ok())
               {
                  if (status = set_mode(mode); status.ok())
                  {
                     generate_uid();
                  }
               }
            }
            if (status.nok())
            {
               socket_.close();
            }
            return status;
         }

         status_t accept(socket_base_t& client, ip::address_t& addr, socket_mode_t mode = socket_mode_t::blocking) const noexcept
         {
            sockaddr name;
            socklen_t namelen;
            status_t status = socket_.accept(client.socket_.handle, &name, &namelen);
            if (status.ok())
            {
               if (status = client.set_mode(mode); status.ok())
               {
                  client.generate_uid();
               }
            }
            return status;
         }

         status_t accept(socket_base_t& client, wait_timeout_t timeout_ms, socket_mode_t mode = socket_mode_t::blocking) const noexcept
         {
            status_t status = wait(socket_event_t::accept_ready, timeout_ms);
            if (status.ok())
            {
               status = accept(client, mode);
            }
            return status;
         }

         status_t send(const char* buffer, size_t len, size_t& bytes_sent, wait_timeout_t timeout_ms) const noexcept
         {
            status_t status = wait(socket_event_t::send_ready, timeout_ms);
            if (status.ok())
            {
               status = send(buffer, len, bytes_sent);
            }
            return status;
         }

         template <ContiguousContainer T>
         status_t send(const T& buffer, size_t& index, wait_timeout_t timeout_ms = SOCKET_WAIT_FOREVER) const noexcept
         {
            status_t status;
            if (index >= buffer.size()) return status;
            size_t bytes_sent{ 0 };
            if (status = send(buffer.data() + index, (buffer.size() - index), bytes_sent, timeout_ms); status.ok())
            {
               index += bytes_sent;
            }
            return status;
         }

         template <ContiguousContainer T>
         status_t send_all(const T& buffer, size_t& bytes_sent, wait_timeout_t timeout_ms = SOCKET_WAIT_FOREVER) noexcept
         {
            size_t index{ 0 };
            status_t status;
            bytes_sent = 0;
            if (buffer.empty()) return status;
            while (status.ok() && index < buffer.size())
            {
               size_t counter = 0;
               if (status = send(buffer.data() + index, (buffer.size() - index), counter); status.ok())
               {
                  bytes_sent += counter;
               }
            }
            return status;
         }
         
         status_t recv(char* buffer, size_t len, size_t& bytes_received, wait_timeout_t timeout_ms) const noexcept
         {
            status_t status = wait(socket_event_t::recv_ready, timeout_ms);
            if (status.ok())
            {
               status = recv(buffer, len, bytes_received);
            }
            return status;
         }

         template <ContiguousContainer T>
         status_t recv(T& buffer, size_t& bytes_received, wait_timeout_t timeout_ms = SOCKET_WAIT_FOREVER) const noexcept
         {
            size_t original_size = buffer.size();
            buffer.resize(original_size + SOCKET_RECV_SIZE);
            bytes_received = 0;
            status_t status = recv(buffer.data() + original_size, SOCKET_RECV_SIZE, bytes_received, timeout_ms);
            buffer.resize(original_size + bytes_received);
            return status;
         }

         template <ContiguousContainer T>
         status_t recv_all(T& buffer, size_t bytes_to_receive, size_t& bytes_received, wait_timeout_t timeout_ms = SOCKET_WAIT_FOREVER) const noexcept
         {
            status_t status;
            size_t original_size = buffer.size();
            size_t index{ original_size };
            bytes_received = 0;
            if (bytes_to_receive == 0) return status_t(WSAEINVAL);
            buffer.resize(original_size + bytes_to_receive);
            while (status.ok() && bytes_to_receive > 0)
            {
               size_t count{};
               if (status = recv(buffer.data() + index, bytes_to_receive, count, timeout_ms); status.ok())
               {
                  if (count == 0) return status;
                  bytes_to_receive -= count;
                  bytes_received += count;
                  index += count;
               }
            }
            return status;
         }

         // timeout_us specifies how long wait will wait until an event occurs
         // SOCKET_WAIT_FOREVER to block until an event occurs
         // SOCKET_WAIT_NEVER to return immediately after checking
         // greater than zero value sets milli-seconds to wait until event occurs
         // wait succeeds:
         //    status_t::ok() == true, status_t::nok() == false, status_t::would_block() == false
         //
         // wait timeout
         //    status_t::ok() == false, status_t::nok() == true, status_t::would_block() == true
         // 
         // wait fails
         //    status_t::ok() == false, status_t::nok() == true, status_t::would_block() == false
         status_t wait(socket_event_t event, wait_timeout_t timeout_ms = SOCKET_WAIT_NEVER) const noexcept
         {
            using enum socket_event_t;
            int connect_flags = (POLLHUP | POLLERR | POLLWRNORM);
            WSAPOLLFD fdset;
            fdset.fd = socket_;
            fdset.revents = 0;
            fdset.events = set_events(event);
            int count{};
            status_t status{ socket_.poll(&fdset, 1, count, timeout_ms) };
            if (status.ok())
            {
               if (count == 0) return status_t(WSAEWOULDBLOCK);
               if (event == connect_ready && (fdset.revents & connect_flags) == connect_flags) return status_t(WSAECONNREFUSED);
               if (event == connect_ready && fdset.events & POLLWRNORM) return status_t(0);
               return (fdset.events & (POLLHUP | POLLRDNORM | POLLWRNORM)) ? status : status_t(WSAEWOULDBLOCK);
            }
            return status;
         }

      private:
         void generate_uid() const noexcept
         {
            static std::atomic_uint64_t counter{ 1 };
            uid_ = counter.fetch_add(1, std::memory_order_relaxed);
         }

         SHORT set_events(socket_event_t event) const noexcept
         {
            using enum socket_event_t;
            if (event == send_recv_ready) return (POLLRDNORM | POLLWRNORM);
            return (event == recv_ready || event == accept_ready) ? POLLRDNORM : POLLWRNORM;
         }

         status_t send(const char* buffer, size_t len, size_t& bytes_sent) noexcept
         {
            return status_t(socket_.send(buffer, len, bytes_sent));
         }

         // if status_t::ok() == true and bytes_received == 0, then peer closing connection
         status_t recv(char* buffer, size_t len, size_t& bytes_received) const noexcept
         {
            return status_t(socket_.recv(buffer, len, bytes_received));
         }

      }; // class socket_base_t

      using socket_t = socket_base_t<bsd::socket_t>;

   } // namespace tcp

   namespace utility {

      /**********************************************************************\
      *
      *  winsock_init_t
      *  Windows socket initialization. DO NOT INSTANTIATE THIS CLASS
      *
      \**********************************************************************/

      class winsock_init_t
      {
         mutable WSADATA wd_;
         int code_{};

      public:
         winsock_init_t() noexcept
         {
            code_ = ::WSAStartup(MAKEWORD(2, 2), &wd_);
         }

         ~winsock_init_t() noexcept
         {
            ::WSACleanup();
         }

         int code() const noexcept
         {
            return code_;
         }

         winsock_init_t(const winsock_init_t&) = delete;
         winsock_init_t(winsock_init_t&&) = delete;
         winsock_init_t& operator=(const winsock_init_t&) = delete;
         winsock_init_t& operator=(winsock_init_t&&) = delete;
      }; // class socket_init_t

      inline const static winsock_init_t socket_startup_;

      class openssl_t
      {
         inline static std::atomic_uint32_t counter_{ 0 };

      public:
         // no copy or move allowed
         openssl_t(const openssl_t&) = delete;
         openssl_t(openssl_t&&) noexcept = delete;
         openssl_t& operator=(const openssl_t&) = delete;
         openssl_t& operator=(openssl_t&&) noexcept = delete;

         openssl_t() noexcept
         {
            initialize();
         }

         ~openssl_t() noexcept
         {
            cleanup();
         }

      private:
         static void initialize() noexcept
         {
            if (counter_.fetch_add(1, std::memory_order_relaxed) == 0)
            {
               SSL_library_init();
               ERR_load_crypto_strings();
               SSL_load_error_strings();
               OpenSSL_add_all_algorithms();
            }
         }

         static void cleanup() noexcept
         {
            if (counter_.fetch_sub(1, std::memory_order_relaxed) == 1)
            {
               ERR_free_strings();
               EVP_cleanup();
               CRYPTO_cleanup_all_ex_data();
               SSL_COMP_free_compression_methods();
            }
         }
      }; // class openssl_t

      inline const static openssl_t openssl_startup_;

      struct X509_deleter
      {
         void operator()(X509* certificate) const
         {
            if (certificate)
            {
               X509_free(certificate);
            }
         }
      };

   } // namespace startup


} // namespace netpune