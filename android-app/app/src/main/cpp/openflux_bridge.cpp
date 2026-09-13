#include <jni.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstddef>
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

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;

    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);

    socklen_t addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1);
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), addrLen) != 0) {
        close(sock);
        return -1;
    }

    char marker = 'F';
    iovec iov{};
    iov.iov_base = &marker;
    iov.iov_len = 1;

    char control[CMSG_SPACE(sizeof(int))]{};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == nullptr) {
        close(sock);
        return -1;
    }
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(cmsg), &tunFd, sizeof(int));
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    ssize_t sent = sendmsg(sock, &msg, 0);
    close(sock);
    return sent == 1 ? 0 : -1;
}
