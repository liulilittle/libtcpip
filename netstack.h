#pragma once

#include "libtcpip.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#include <functional>
#include <memory>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#ifdef _WIN32
namespace boost { // boost::asio::posix::stream_descriptor
    namespace asio {
        namespace posix {
            typedef boost::asio::windows::stream_handle stream_descriptor;
        }
    }
}
#include <WinSock2.h>
#else
namespace boost {
    namespace asio {
        typedef io_service io_context;
    }
}
#endif

namespace lwip {
    class netstack {
    public:
        static bool                                         open() noexcept;
        static void                                         close() noexcept;

    public:
        static LIBTCPIP_IPV4_OUTPUT                         output;
        static uint32_t                                     IP;
        static uint32_t                                     GW;
        static uint32_t                                     MASK;
        static int                                          Localhost;
        static bool                                         input(const void* packet, int size) noexcept;
        static bool                                         link(int nat, uint32_t& srcAddr, int& srcPort, uint32_t& dstAddr, int& dstPort) noexcept;
    };
}