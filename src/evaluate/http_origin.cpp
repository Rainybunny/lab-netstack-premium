/**
 * @file http_origin.cpp
 * @brief Minimal HTTP origin server running on the user-space TCP stack.
 *
 * Usage: http_origin PORT
 *
 * Serves a fixed HTML page to every accepted connection and closes. Used by
 * the CL8 proxy test.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

const char BODY[] =
    "<html><head><title>lab3 origin</title></head>"
    "<body><h1>lab3 origin</h1>"
    "<p>served through the user-space TCP stack</p></body></html>\n";

bool writeAll(int fd, const void* buffer, size_t length) {
    size_t done = 0;
    const auto* bytes = static_cast<const uint8_t*>(buffer);
    while (done < length) {
        const ssize_t count = write(fd, bytes + done, length - done);
        if (count <= 0) {
            return false;
        }
        done += size_t(count);
    }
    return true;
}

bool readRequest(int fd, std::string& request) {
    request.clear();
    char buffer[1024];
    while (request.size() < 8192) {
        const ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count <= 0) {
            return false;
        }
        request.append(buffer, size_t(count));
        if (request.find("\r\n\r\n") != std::string::npos) {
            return true;
        }
    }
    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc != 2) {
        fprintf(stderr, "usage: %s PORT\n", argv[0]);
        return 1;
    }
    const int port = std::atoi(argv[1]);

    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        return 1;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(uint16_t(port));
    if (bind(listener, reinterpret_cast<sockaddr*>(&address),
             sizeof(address)) < 0 ||
        listen(listener, 4) < 0) {
        perror("bind/listen");
        return 1;
    }
    printf("ORIGIN listening on %d\n", port);

    for (int connection = 0; connection < 4; ++connection) {
        const int fd = accept(listener, nullptr, nullptr);
        if (fd < 0) {
            perror("accept");
            return 1;
        }
        std::string request;
        if (!readRequest(fd, request)) {
            close(fd);
            continue;
        }
        const size_t lineEnd = request.find("\r\n");
        printf("ORIGIN request: %s\n",
               request.substr(0, lineEnd).c_str());

        char response[512];
        const int headerLength = std::snprintf(
            response, sizeof(response),
            "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n"
            "Content-Length: %zu\r\nConnection: close\r\n\r\n",
            std::strlen(BODY));
        writeAll(fd, response, size_t(headerLength));
        writeAll(fd, BODY, std::strlen(BODY));
        close(fd);
    }
    close(listener);
    return 0;
}
