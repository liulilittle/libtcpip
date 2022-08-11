#include "libtcpip.h"
#include "netstack.h"

LIBTCPIP_API
bool libtcpip_loopback(int localhost, uint32_t ip, uint32_t gw, uint32_t mask, LIBTCPIP_IPV4_OUTPUT outputfn) noexcept {
    if (ip == INADDR_ANY || ip == INADDR_NONE) {
        return false;
    }

    if (gw == INADDR_ANY || gw == INADDR_NONE) {
        return false;
    }

    if (mask == INADDR_ANY || !outputfn) {
        return false;
    }

    lwip::netstack::output = outputfn;
    lwip::netstack::IP = ip;
    lwip::netstack::GW = gw;
    lwip::netstack::MASK = mask;
    lwip::netstack::Localhost = localhost;
    return lwip::netstack::open();
}

LIBTCPIP_API
bool libtcpip_input(void* packet, int size) noexcept {
    if (!packet || size < 1) {
        return false;
    }
    return lwip::netstack::input(packet, size);
}

LIBTCPIP_API
bool libtcpip_link(int nat, uint32_t& srcAddr, int& srcPort, uint32_t& dstAddr, int& dstPort) noexcept {
    return lwip::netstack::link(nat, srcAddr, srcPort, dstAddr, dstPort);
}

template <class _Ty>
struct libtcpip_default_delete { // default deleter for unique_ptr
    inline constexpr libtcpip_default_delete() noexcept = default;

    template <class _Ty2, std::enable_if_t<std::is_convertible_v<_Ty2*, _Ty*>, int> = 0>
    inline libtcpip_default_delete(const libtcpip_default_delete<_Ty2>&) noexcept {}

    inline void operator()(_Ty* _Ptr) const noexcept /* strengthened */ { // free a pointer
        static_assert(0 < sizeof(_Ty), "can't delete an incomplete type");

        _Ptr->~_Ty();
        free(_Ptr);
    }
};

typedef
void(*LIBTCPIP_LOOP_STREAM_CALLBACK)(int state, int length);

typedef std::shared_ptr<boost::asio::posix::stream_descriptor>                  StreamPtr;
typedef std::unordered_map<boost::asio::posix::stream_descriptor*, StreamPtr>   StreamMap;
typedef std::mutex                                                              Mutex;
typedef std::lock_guard<Mutex>                                                  MutexScope;
static boost::asio::io_context                                                  context_;
static StreamMap                                                                streams_;
static Mutex                                                                    lockobj_;

LIBTCPIP_API void
libtcpip_stop_stream(void* handle) noexcept {
    if (handle) {
        MutexScope scope_(lockobj_);
        StreamMap::iterator tail_ = streams_.find((boost::asio::posix::stream_descriptor*)handle);
        StreamMap::iterator endl_ = streams_.end();
        if (tail_ != endl_) {
            std::shared_ptr<boost::asio::posix::stream_descriptor>& stream_ = tail_->second;
            if (stream_) {
                boost::system::error_code ec_;
                stream_->close(ec_);
            }
            streams_.erase(tail_);
        }
    }
}

LIBTCPIP_API bool
libtcpip_write_stream(void* handle, void* buffer, int length) noexcept {
    if (!buffer || length < 1) {
        return false;
    }

    void* chunk = (void*)malloc(length);
    if (!chunk) {
        return false;
    }

    std::shared_ptr<char> packet_ = std::shared_ptr<char>((char*)chunk, free);
    memcpy(chunk, buffer, length);

    if (handle) {
        MutexScope scope_(lockobj_);
        StreamMap::iterator tail_ = streams_.find((boost::asio::posix::stream_descriptor*)handle);
        StreamMap::iterator endl_ = streams_.end();
        if (tail_ != endl_) {
            std::shared_ptr<boost::asio::posix::stream_descriptor>& stream_ = tail_->second;
            if (stream_) {
                stream_->async_write_some(boost::asio::buffer(chunk, length), [packet_](const boost::system::error_code& ec_, size_t sz) {});
                return true;
            }
        }
    }
    return false;
}

static void*
libtcpip_read_stream(void* handle, void* buff, int length, int state, LIBTCPIP_LOOP_STREAM_CALLBACK callback) noexcept {
    if (!handle || !buff || length < 1 || !callback) {
        return NULL;
    }

    MutexScope scope_(lockobj_);
    StreamMap::iterator tail_ = streams_.find((boost::asio::posix::stream_descriptor*)handle);
    StreamMap::iterator endl_ = streams_.end();
    if (tail_ == endl_) {
        return NULL;
    }

    std::shared_ptr<boost::asio::posix::stream_descriptor> stream_ = tail_->second;
    if (!stream_ || !stream_->is_open()) {
        return NULL;
    }

    stream_->async_read_some(boost::asio::buffer(buff, length), [handle, buff, length, state, callback](const boost::system::error_code& ec_, size_t sz) {
        int by = std::max<int>(-1, ec_ ? -1 : sz);
        callback(state, by);

        if (by < 0 || !libtcpip_read_stream(handle, buff, length, state, callback)) {
            libtcpip_stop_stream(handle);
        }
    });
    return handle;
}

LIBTCPIP_API void*
libtcpip_loop_stream(void* handle, void* buff, int length, int state, LIBTCPIP_LOOP_STREAM_CALLBACK callback) noexcept {
    if (!handle || !buff || length < 1 || !callback) {
        return NULL;
    }

    void* memory_ = malloc(sizeof(boost::asio::posix::stream_descriptor));
    boost::asio::posix::stream_descriptor* key_ = NULL;
    try {
        key_ = new (memory_) boost::asio::posix::stream_descriptor(context_, handle);
    }
    catch (std::exception&) {
        free(memory_);
        return NULL;
    }

    std::shared_ptr<boost::asio::posix::stream_descriptor> stream_ = std::shared_ptr<boost::asio::posix::stream_descriptor>(key_,
        libtcpip_default_delete<boost::asio::posix::stream_descriptor>());
    do {
        MutexScope scope_(lockobj_);
        streams_.insert(std::make_pair(key_, stream_));
    } while (0);
    return libtcpip_read_stream(key_, buff, length, state, callback);
}

static void
libtcpip_initialize() throw() {
    static std::thread loopback_([] {
#ifdef _WIN32
        SetThreadPriority(GetCurrentProcess(), THREAD_PRIORITY_TIME_CRITICAL);
#else
        /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
        struct sched_param param_;
        param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR
        pthread_setschedparam(pthread_self(), SCHED_FIFO, &param_);
#endif
        boost::system::error_code ec_;
        boost::asio::io_context::work work_(context_);
        context_.run(ec_);
    });
}

static void
libtcpip_uninitalize() throw() {
    // TODO: Your are code here.
}

BOOL APIENTRY
DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) noexcept {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        libtcpip_initialize();
        break;
    case DLL_PROCESS_DETACH:
        libtcpip_uninitalize();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    };
    return TRUE;
}