#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <netdb.h>
#include <unistd.h>
#include <assert.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#define LINSTEN 1
#define CLIENT 2

struct _stSocket
{
    int fd;
    int type;
};

struct event {
    void * s;
    int read;
    int write;
    unsigned mask;
};

static bool 
sp_invalid(int efd) {
    return efd == -1;
}

static int
sp_create() {
    return epoll_create(1024);
}

static void
sp_release(int efd) {
    close(efd);
}


static int 
sp_add(int efd, int sock, void *ud) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = ud;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &ev) == -1) {
        return 1;
    }
    return 0;
}

static void 
sp_del(int efd, int sock) {
    epoll_ctl(efd, EPOLL_CTL_DEL, sock , NULL);
}

static void 
sp_write(int efd, int sock, void *ud, bool enable) {
    struct epoll_event ev;
    ev.events = EPOLLIN | (enable ? EPOLLOUT : 0);
    ev.data.ptr = ud;
    epoll_ctl(efd, EPOLL_CTL_MOD, sock, &ev);
}

static int 
sp_wait(int efd, struct event *e, int max) {
    struct epoll_event ev[max];
    int n = epoll_wait(efd , ev, max, 5000);
    int i;
    for (i=0;i<n;i++) {
        e[i].s = ev[i].data.ptr;
        unsigned flag = ev[i].events;
        e[i].write = (flag & EPOLLOUT) != 0;
        e[i].read = (flag & EPOLLIN) != 0;
        e[i].mask = flag;
    }

    return n;
}

static void
sp_nonblocking(int fd) {
    int flag = fcntl(fd, F_GETFL, 0);
    if ( -1 == flag ) {
        return;
    }

    fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}


// return -1 means failed
// or return AF_INET or AF_INET6
static int
do_bind(const char *host, int port, int protocol, int *family) {
    int fd;
    int status;
    int reuse = 1;
    struct addrinfo ai_hints;
    struct addrinfo *ai_list = NULL;
    char portstr[16];
    if (host == NULL || host[0] == 0) {
        host = "0.0.0.0";   // INADDR_ANY
    }
    sprintf(portstr, "%d", port);
    memset( &ai_hints, 0, sizeof( ai_hints ) );
    ai_hints.ai_family = AF_UNSPEC;
    if (protocol == IPPROTO_TCP) {
        ai_hints.ai_socktype = SOCK_STREAM;
    } else {
        assert(protocol == IPPROTO_UDP);
        ai_hints.ai_socktype = SOCK_DGRAM;
    }
    ai_hints.ai_protocol = protocol;

    status = getaddrinfo( host, portstr, &ai_hints, &ai_list );
    if ( status != 0 ) {
        return -1;
    }
    *family = ai_list->ai_family;
    fd = socket(*family, ai_list->ai_socktype, 0);
    if (fd < 0) {
        goto _failed_fd;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(int))==-1) {
        goto _failed;
    }
    status = bind(fd, (struct sockaddr *)ai_list->ai_addr, ai_list->ai_addrlen);
    if (status != 0)
        goto _failed;

    freeaddrinfo( ai_list );
    return fd;
_failed:
    close(fd);
_failed_fd:
    freeaddrinfo( ai_list );
    return -1;
}

int
main() {
    const char* host = "10.123.10.158";
    short port = 8888;
    int efd = sp_create();
    int family = 0;
    int listen_fd = do_bind(host, port, IPPROTO_TCP, &family);
    if (listen_fd < 0) {
        return -1;
    }
    if (listen(listen_fd, 32) == -1) {
        close(listen_fd);
        return -1;
    }

    struct _stSocket *ud = (struct _stSocket*)malloc(sizeof(struct _stSocket));
    ud->fd = listen_fd;
    ud->type = LINSTEN;
    printf("%s:%d =======> linsten ok port:[%s:%d] ud->fd:%d\n", __FUNCTION__, __LINE__, host, port, ud->fd);

    sp_add(efd, listen_fd, ud);

    struct event ev[64];

    while(1)
    {
        int cnt = sp_wait(efd, ev, 64);
        if (cnt < 0)
        {
            printf("%s:%d\n", __FUNCTION__, __LINE__);
            continue;
        }
        else
        {
            int i;
            for (i = 0; i < cnt; ++i)
            {
                struct event x = ev[i];
                printf("%s:%d i:%d xxxxx mask:%d, read:%d, write:%d\n", __FUNCTION__, __LINE__, i, x.mask, x.read, x.write);
                if (x.read)
                {
                    ud = (struct _stSocket*)(x.s);
                    if (LINSTEN == ud->type)
                    {
                        struct sockaddr si;
                        socklen_t len = sizeof(si);
                        int client_fd = accept(ud->fd, &si, &len);
                        struct _stSocket* cl = (struct _stSocket*)malloc(sizeof(struct _stSocket));
                        cl->fd = client_fd;
                        cl->type = CLIENT;
                        sp_add(efd, client_fd, cl);
                        printf("ud:%d,accept client_fd:%d\n", ud->fd, cl->fd);
                    }
                    else if (CLIENT == ud->type)
                    {
                        // printf("%s:%d i:%d CLIENT mask:%d, read:%d, write:%d\n", __FUNCTION__, __LINE__, i, x.mask, x.read, x.write);
                        char buff[256];
                        int blen = 256;
                        int ret = read(ud->fd, buff, blen);
                        if (ret < 0)
                        {
                            fprintf(stderr, "socket-server : read pipe error %s.\n",strerror(errno));
                            sp_del(efd, ud->fd);
                        }
                        else if (ret == 0)
                        {
                            fprintf(stderr, "socket-server : read pipe ret 0 %s.\n",strerror(errno));
                            sp_del(efd, ud->fd);
                        }
                        else
                        {
                            buff[blen] = '\0';
                            fprintf(stderr, "socket-server : read pipe ret :%d %s\n", ret, buff);
                        }
                    }
                }
                if (x.write)
                {

                }

            }
        }
    }

    return 0;
}
