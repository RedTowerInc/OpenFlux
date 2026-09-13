#include <jni.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <string>

extern "C" JNIEXPORT jint JNICALL
Java_com_openflux_android_NativeBridge_sendFd(JNIEnv* env, jclass, jint tunFd, jstring socketPath) {
    if (tunFd < 0 || socketPath == nullptr) return -1;

    const char* raw = env->GetStringUTFChars(socketPath, nullptr);
    if (raw == nullptr) return -1;
    std::string path(raw);
    env->ReleaseStringUTFChars(socketPath, raw);

    sockaddr_un addr{};
    if (path.empty() || path.size() >= sizeof(addr.sun_path)) return -1;

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    // Match upstream badvpn/libancillary behavior exactly. The tun2socks
    // listener binds using sizeof(sockaddr_un), so connect with the same size.
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    // Equivalent to libancillary ancil_send_fd().
    struct {
        cmsghdr h;
        int fd;
    } control{};

    char marker = '!';
    iovec iov{};
    iov.iov_base = &marker;
    iov.iov_len = 1;

    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &control;
    msg.msg_controllen = sizeof(cmsghdr) + sizeof(int);

    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == nullptr) {
        close(sock);
        return -1;
    }
    cmsg->cmsg_len = msg.msg_controllen;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *reinterpret_cast<int*>(CMSG_DATA(cmsg)) = tunFd;

    ssize_t sent = sendmsg(sock, &msg, 0);
    close(sock);
    return sent >= 0 ? 0 : -1;
}
