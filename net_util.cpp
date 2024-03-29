//
// CONFIDENTIAL - FORD MOTOR COMPANY
//
// This is an unpublished work, which is a trade secret, created in
// 2017.  Ford Motor Company owns all rights to this work and intends
// to maintain it in confidence to preserve its trade secret status.
// Ford Motor Company reserves the right to protect this work as an
// unpublished copyrighted work in the event of an inadvertent or
// deliberate unauthorized publication.  Ford Motor Company also
// reserves its rights under the copyright laws to protect this work
// as a published work.  Those having access to this work may not copy
// it, use it, or disclose the information contained in it without
// the written authorization of Ford Motor Company.
//
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/route.h>
#ifdef __QNXNTO__
#include <net/if_gre.h>
#include <net/if_vlanvar.h>
#else
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#endif
#include <sys/ioctl.h>
#include <unistd.h>
#include <cerrno>
#include <string>
#include <logger_api.hpp>
#include <net_util.h>
#include <type_util.h>

static Logger &logger( *Logger::getInstance( "libvnm" ) );
static Logger& loggerSp(*Logger::getInstanceTo(LoggerBufferSP, "libvnm"));

namespace fnv {
namespace vnm {
const size_t BITS_IN_IPV4ADDR = 32;

#ifdef __QNXNTO__
struct RtMsg {
    struct rt_msghdr rt;
    struct sockaddr_in dst;
    struct sockaddr_in gwy;
    struct sockaddr_in msk;
};


static int SetSockFib( int sockfd, size_t fib ) {
    int rc = setsockopt( sockfd, SOL_SOCKET, SO_SETFIB, &fib, sizeof fib );
    if (rc) {
        rc = errno; //NOSONAR
        logger.w( "%s(%d): Setting fib socket option: rc=%d.", __FUNCTION__, __LINE__, rc );
    }
    return rc;
}
#else
static int SetSockFib( int /*sockfd*/, size_t /*fib*/ ) {
    return 0;
}
#endif // __QNXNTO__


static int AllocateSocket( int domain, size_t fib, int* sockrc ) {
    const int type = ((domain==AF_INET) ? SOCK_DGRAM : SOCK_RAW) | SOCK_CLOEXEC;
    int sockfd = socket( domain, type, 0 );
    if (sockfd<0) {
        if (sockrc) {
            *sockrc = errno;
            logger.e( "Could not allocate socket, rc=%d", *sockrc ); //NOSONAR
        }
        else {
            logger.e( "Could not allocate socket, rc=%d", errno ); //NOSONAR
        }
    } else {
        int rc = SetSockFib( sockfd, fib );
        if (rc) {
            logger.e( "Could not set fib socket option, rc=%d", rc );
            close( sockfd );
            sockfd = -1;
        }
        if (sockrc) {
            *sockrc = rc;
        }
    }
    return sockfd;
}

static int AllocateInetSocket( size_t fib, int* sockrc=nullptr) {
    return AllocateSocket( AF_INET, fib, sockrc );
}

#ifdef __QNXNTO__
static int AllocateRouteSocket( size_t fib, int* sockrc ) {
    return AllocateSocket( AF_ROUTE, fib, sockrc );
}

static int PerformRoutingOps( struct RtMsg *rtmsg, const std::string &gateway, __attribute__((unused)) size_t fib ) {
    int rc=0;

    rtmsg->rt.rtm_msglen = sizeof *rtmsg;
    rtmsg->rt.rtm_version = RTM_VERSION;
    rtmsg->rt.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
    rtmsg->rt.rtm_seq = 1234;
    rtmsg->rt.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    rtmsg->rt.rtm_pid = getpid();

    rtmsg->dst.sin_len    = sizeof rtmsg->dst;
    rtmsg->dst.sin_family = AF_INET;
    rtmsg->gwy.sin_len    = sizeof rtmsg->gwy;
    rtmsg->gwy.sin_family = AF_INET;
    rtmsg->msk.sin_len    = sizeof rtmsg->msk;
    rtmsg->msk.sin_family = AF_INET;
    inet_aton( gateway.c_str(), &rtmsg->gwy.sin_addr );

    const int sockfd = AllocateRouteSocket( fib, &rc );
    if (sockfd<0) {
        logger.e( "%s: Could not create routing socket, rc=%d.", __FUNCTION__, rc );
        return rc;
    }

    const ssize_t w = write( sockfd, &rtmsg->rt, rtmsg->rt.rtm_msglen );
    if (w<1) {
        rc = errno; //NOSONAR
    }

    close( sockfd );

    if (rc) {
        logger.e( "%s: Setting/Deleting default route: rc=%d.", __FUNCTION__, rc );
        return rc;
    }

    return EOK;
}
#endif // __QNXNTO__


//
// Obtain the IPv4 address of the interface network interface named.
// If the interface isn't found or doesn't have an address, the
// returned string is empty.
std::string GetIfAddress( const std::string &ifnm, __attribute__((unused)) size_t fibno ) {
    int rc;
    struct ifaddrs *ifap=nullptr;
    struct sockaddr_in *sa_inp=nullptr;

#ifdef __QNXNTO__
    if (fibno>0) {
        rc = getifaddrs_fib( &ifap, fibno );
    } else {
        rc = getifaddrs( &ifap );
    }
#else
    rc = getifaddrs( &ifap );
#endif
    if (!rc) {
        for (struct ifaddrs *ifp = ifap; ifp; ifp=ifp->ifa_next) {
            if (ifp->ifa_addr && ifp->ifa_addr->sa_family==AF_INET) {
                if (ifnm == ifp->ifa_name) {
                    sa_inp = BufferAs< struct sockaddr_in >( AsBuffer( ifp->ifa_addr ) );
                }
            }
        }
    }
    std::string result;
    if (sa_inp) {
        char buf[32];
        const char *p = ::inet_ntop( AF_INET, &sa_inp->sin_addr.s_addr, buf, sizeof buf );
        if (p) {
            result.assign( p );
        }
    }
    if (ifap) {
        freeifaddrs( ifap );
    }
    return result;
}

//
// Search for a network interface with the IPv4 address given.
// If no qualifying interface is found, the returned string is empty.
std::string FindIfName( const std::string &ipaddr, __attribute__((unused)) size_t fibno ) {
    int rc;
    struct ifaddrs *ifap=nullptr;
    struct in_addr addr;
    std::string result;

    rc = inet_pton( AF_INET, ipaddr.c_str(), &addr );
    if (rc != 1) {
        return "";
    }
#ifdef __QNXNTO__
    if (fibno>0) {
        rc = getifaddrs_fib( &ifap, fibno );
    } else {
        rc = getifaddrs( &ifap );
    }
#else
    rc = getifaddrs( &ifap );
#endif
    if (!rc) {
        for (struct ifaddrs *ifp = ifap; ifp; ifp=ifp->ifa_next) {
            if (ifp->ifa_addr && ifp->ifa_addr->sa_family==AF_INET) {
                if (addr.s_addr == BufferAs< struct sockaddr_in >( AsBuffer( ifp->ifa_addr ) )->sin_addr.s_addr) {
                    result = ifp->ifa_name;
                    break;
                }
            }
        }
    }

    if (ifap) {
        freeifaddrs( ifap );
    }
    return result;
}

#if 0
// Produce a vlan ID based on bits 2-11 of a v4 address.
// The IP address is passed in dotted decimal.
// 0 is not a suitable ID and indicates error.
// The bits harvested are bits 2-11 counting from lsb.
// The bit value is added to 10 to yield a number 10 and up.
// This function serves a temporary need only.
size_t VlanIdFromV4Address( const std::string &ipaddr ) {
    struct in_addr addr;
    int rc = inet_pton( AF_INET, ipaddr.c_str(), &addr );
    if (rc != 1) {
        return 0;
    }
    const size_t field = 0x2FF & ntohl( addr.s_addr ) >> 2;
    return field+10;
}
#endif
//
// Produce an IPv4 addess based on components:
// Prefix:   The most significant prefixlen bits
// Subnetno: The subsequent less significant subnetlen bits
// hostno:   The least significant remaining bits; right of the subnet mask.
size_t Ipv4AddrFromBits( size_t prefix, size_t prefixlen, size_t subnetno, size_t subnetlen, size_t hostno ) {
    size_t address;
    if (prefixlen > BITS_IN_IPV4ADDR) {
        return 0;
    }
    if (subnetlen > BITS_IN_IPV4ADDR) {
        return 0;
    }
    if ((subnetlen+prefixlen) > BITS_IN_IPV4ADDR) {
        return 0;
    }
    address = prefix << (BITS_IN_IPV4ADDR-prefixlen);
    address |= subnetno << (BITS_IN_IPV4ADDR-prefixlen-subnetlen);
    address |= hostno;
    return htonl( address );
}

std::string StringFromIpv4Addr( size_t ipaddr ) {
    std::string result;
    char buf[32];
    const char *p = ::inet_ntop( AF_INET, &ipaddr, buf, sizeof buf );
    result.assign( p );
    return result;
}


//
// Determine whether a string is a well-formed dotted quad IP v4 address.
// A true return indicates that it is.
bool ValidateIpv4Address( const std::string &ipaddr ) {
  int rc;
  struct in_addr addr;
  rc = inet_pton( AF_INET, ipaddr.c_str(), &addr );
  return 1==rc;
}

//
// Confirm that the passed string matches the name of an interface that is UP.
bool ValidateIfname( const std::string &ifnm ) {
    int rc;
    struct ifaddrs *ifap=nullptr;
    bool result=false;

    rc = getifaddrs( &ifap );
    if (!rc) {
        for (struct ifaddrs *ifp = ifap; ifp; ifp=ifp->ifa_next) {
            if ((ifp->ifa_flags & IFF_UP) && (ifnm == ifp->ifa_name)) {
                result = true;
                break;
            }
        }
    }

    if (ifap) {
        freeifaddrs( ifap );
    }
    return result;
}


bool Ipv4AddrFromString( const std::string &ip_string, struct in_addr &addr ) {
    int rc;
    rc = inet_pton( AF_INET, ip_string.c_str(), &addr );
    if (1!=rc) {
        logger.e( "ERROR %s: %d", __FUNCTION__, rc );
        return false;
    }

    return true;
}


int Ipv4Prefixlen2Mask( int prefix, uint32_t &mask)
{
    if (prefix > 32 || prefix < 0) {
        return EINVAL;
    }
    if (prefix) {
        mask = htonl(~((1 << (32 - prefix)) - 1));
    } else {
        mask = htonl(0);
    }
    return 0;
}


int GetIfaceFlags( const std::string &name, unsigned long &flags, size_t fib ) {
    struct ifreq ifr{};
    if (name.length() >= sizeof ifr.ifr_name) {
        return EINVAL;
    }
    strncpy( ifr.ifr_name, name.c_str(), sizeof ifr.ifr_name - 1);
    int rcerrno = 0;
    const int sockfd = AllocateInetSocket( fib, &rcerrno );
    if (sockfd==-1) {
        return rcerrno;
    }
    int rc = ioctl( sockfd, SIOCGIFFLAGS, &ifr );
    if (rc) {
        rc = errno; //NOSONAR
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCGIFFLAGS: rc=%d", rc );
        return rc;
    }

    flags = ifr.ifr_flags;
    return 0;
}


#ifdef __QNXNTO__
static int SetIfaceFlags( const std::string &name, long flag, size_t fib ) {
    struct ifreq ifr{};
    if (name.length() >= sizeof ifr.ifr_name) {
        return EINVAL;
    }
    strncpy( ifr.ifr_name, name.c_str(), sizeof ifr.ifr_name - 1);

    unsigned long flags=0;
    int rc;
    rc = GetIfaceFlags( name, flags, fib );
    if (rc) {
        return rc;
    }
    int rcerrno = 0;
    const int sockfd = AllocateInetSocket( fib , &rcerrno);
    if (sockfd==-1) {
        return rcerrno; //NOSONAR
    }
    if (flag>0) {
        ifr.ifr_flags = (flags | flag);
    } else {
        flag = -flag;
        ifr.ifr_flags = (flags & ~flag);
    }

    rc = ioctl( sockfd, SIOCSIFFLAGS, &ifr );
    if (rc) {
        rc = errno; //NOSONAR
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCSIFFLAGS: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Iface flags set, interface name: %s.",  name.c_str());
    return 0;
}
#endif

static int SetIfaceAddrField( const std::string &name, unsigned long request, const struct sockaddr_in &sa, size_t fib ) {
    struct ifreq ifr{};
    if (name.length() >= sizeof ifr.ifr_name) {
        return EINVAL;
    }
    strncpy( ifr.ifr_name, name.c_str(), sizeof ifr.ifr_name - 1);

    const int sockfd = AllocateInetSocket( fib );
    if (sockfd==-1) {
        return errno; //NOSONAR
    }
    ifr.ifr_addr = *(struct sockaddr*) &sa;
    int rc = ioctl( sockfd, request, &ifr );
    if (rc) {
        rc = errno; //NOSONAR
    }
    close( sockfd );

    return rc;
}

static int SetIfaceAddrField( const std::string &name, unsigned long request, const std::string &addr_string, size_t fib ) {
    struct sockaddr_in sa{};
    size_t slashIndex = addr_string.find("/");
    std::string ipaddress = slashIndex != std::string::npos? addr_string.substr(0, slashIndex): addr_string;
    std::string subnet = slashIndex != std::string::npos? addr_string.substr(slashIndex + 1): "";

#ifdef __QNXNTO__
    sa.sin_len = sizeof sa;
#endif

    bool success = true;
    if (!ipaddress.empty()) {
        sa.sin_family = AF_INET;
        success = Ipv4AddrFromString( ipaddress, sa.sin_addr );
    }
    if (!success) {
        return EINVAL;
    }
    int rc = SetIfaceAddrField( name, request, sa, fib );
    if (!rc && subnet.length() > 0) {
        rc = SetIfaceNetPrefixLen ( name, atoi(subnet.c_str()), fib);
    }

    return rc;
}

#ifdef __QNXNTO__
int CreateCloneIface( const std::string &name, size_t fib ) {
    struct ifreq ifr{};
    if (name.length() >= sizeof ifr.ifr_name) {
        return EINVAL;
    }
    strncpy( ifr.ifr_name, name.c_str(), sizeof ifr.ifr_name - 1);
    int sockrc;
    const int sockfd = AllocateInetSocket( fib, &sockrc );
    if (sockfd==-1) {
        return sockrc; //NOSONAR
    }

    int rc = ioctl( sockfd, SIOCIFCREATE, &ifr );
    if (rc) {
        rc = errno; //NOSONAR
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCIFCREATE: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Iface created, interface name: %s.", name.c_str() );
    return 0;
}
#else
int CreateCloneIface( __attribute__((unused)) const std::string &name, __attribute__((unused)) size_t fib ) {
    return ENOTSUP;
}
#endif


#ifdef __QNXNTO__
int CreateVlanIface( __attribute__((unused)) const std::string &parent, __attribute__((unused)) size_t vlanid ) {
    return ENOTSUP;
}
#else
int CreateVlanIface( const std::string &parent, size_t vlanid ) {
    struct vlan_ioctl_args ifr{};
    if (parent.length() >= sizeof ifr.device1 ) {
        return EINVAL;
    }
    strncpy( ifr.device1, parent.c_str(), sizeof ifr.device1 - 1 );
    ifr.cmd = ADD_VLAN_CMD;
    ifr.u.VID = vlanid;
    int sockrc;
    const int sockfd = AllocateInetSocket( 0, &sockrc );
    if (sockfd==-1) {
        return sockrc;
    }
    int rc = ioctl( sockfd, SIOCSIFVLAN, &ifr );
    if (rc) {
        rc = errno;
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCSIFVLAN: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Iface created.");
    return 0;
}
#endif


#ifdef __QNXNTO__
int DestroyCloneIface( const std::string &name, size_t fib ) {
    struct ifreq ifr{};
    if (name.length() >= sizeof ifr.ifr_name) {
        return EINVAL;
    }
    strncpy( ifr.ifr_name, name.c_str(), sizeof ifr.ifr_name - 1);

    const int sockfd = AllocateInetSocket( fib );
    if (sockfd==-1) {
        return errno; //NOSONAR
    }

    int rc = ioctl( sockfd, SIOCIFDESTROY, &ifr );
    if (rc) {
        rc = errno; //NOSONAR
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCIFDESTROY: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Iface destroyed, interface name: %s.", name.c_str() );
    return 0;
}
#endif

#ifdef __QNXNTO__
int DeleteVlanIface( __attribute__((unused)) const std::string &name ) {
    return ENOTSUP;
}
#else
int DeleteVlanIface( const std::string &name ) {
    struct vlan_ioctl_args ifr{};
    if (name.length() >= sizeof ifr.device1 ) {
        return EINVAL;
    }
    strncpy( ifr.device1, name.c_str(), sizeof ifr.device1 - 1 );
    ifr.cmd = DEL_VLAN_CMD;

    const int sockfd = AllocateInetSocket( 0 );
    if (sockfd==-1) {
        return errno;
    }
    int rc = ioctl( sockfd, SIOCSIFVLAN, &ifr );
    if (rc) {
        rc = errno;
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCSIFVLAN: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Iface deleted, interface name: %s.", name.c_str() );
    return 0;
}
#endif


#ifdef __QNXNTO__
int DeleteTunnel( const std::string &name, size_t fib ) {
    struct ifreq ifr{};
    if (name.length() >= sizeof ifr.ifr_name) {
        return EINVAL;
    }
    strncpy( ifr.ifr_name, name.c_str(), sizeof ifr.ifr_name - 1);

    const int sockfd = AllocateInetSocket( fib );
    if (sockfd==-1) {
        return errno; //NOSONAR
    }

    int rc = ioctl( sockfd, SIOCDIFPHYADDR, &ifr );
    if (rc) {
        rc = errno; //NOSONAR
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCDIFPHYADDR: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Tunnel deleted, name: %s.", name.c_str() );
    return 0;
}
#endif


#ifdef __QNXNTO__
int SetIfaceVlan( const std::string &name, const std::string &parentifnm, int id, size_t fib ) {
    struct ifreq ifr{};
    if (name.length() >= sizeof ifr.ifr_name) {
        return EINVAL;
    }
    strncpy( ifr.ifr_name, name.c_str(), sizeof ifr.ifr_name - 1);

    struct vlanreq vlr;
    if (parentifnm.length() >= sizeof vlr.vlr_parent) {
        return EINVAL;
    }
    if (id>1024) {
        return EINVAL;
    }

    memset( &vlr, 0, sizeof vlr );
    strncpy( vlr.vlr_parent, parentifnm.c_str(), sizeof vlr.vlr_parent - 1 );
    vlr.vlr_tag = id;
    ifr.ifr_data = &vlr;
    int sockrc;
    const int sockfd = AllocateInetSocket( fib, &sockrc );
    if (sockfd==-1) {
        return sockrc; //NOSONAR
    }

    int rc = ioctl( sockfd, SIOCSETVLAN, &ifr );
    if (rc) {
        rc = errno; //NOSONAR
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCSETVLAN: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "vlan iface defined, interface name: %s, parent intf name: %s.", name.c_str(), parentifnm.c_str() );

    return 0;
}

int SetIfaceMtu( const std::string &name, size_t mtu, size_t fib ) {
    struct ifreq ifr{};
    if (name.length() >= sizeof ifr.ifr_name) {
        return EINVAL;
    }
    strncpy( ifr.ifr_name, name.c_str(), sizeof ifr.ifr_name - 1);
    int sockrc;
    const int sockfd = AllocateInetSocket( fib, &sockrc );
    if (sockfd==-1) {
        return sockrc; //NOSONAR
    }
    ifr.ifr_mtu = mtu;
    int rc = ioctl( sockfd, SIOCSIFMTU, &ifr );
    if (rc) {
        rc = errno; //NOSONAR
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCSIFMTU: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "MTU setting succeeded, interface name: %s.", name.c_str() );
    return 0;
}
#endif

#if 0
#ifdef __QNXNTO__
int SetIfaceFib( const std::string &name, size_t fib ) {
    struct ifreq ifr{};
    if (name.length() >= sizeof ifr.ifr_name) {
        return EINVAL;
    }
    strncpy( ifr.ifr_name, name.c_str(), sizeof ifr.ifr_name - 1 );

    const int sockfd = socket( AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0 );
    if (sockfd==-1) {
        return errno; //NOSONAR
    }

    ifr.ifr_value = fib;
    int rc = ioctl( sockfd, SIOCSIFFIB, &ifr );
    if (rc) {
        rc = errno; //NOSONAR
    }
    close( sockfd );

    if (rc) {
        logger.e( "SIOCSIFFIB: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "FIB setting succeeded, name: %s.", name.c_str() );
    return 0;
}
#else
int SetIfaceFib( __attribute__((unused)) const std::string &name,
                 __attribute__((unused)) size_t fib ) {
    return ENOTSUP;
}
#endif
#endif

#ifdef __QNXNTO__
int SetIfaceLink1Flag( const std::string &name, size_t fib ) {
    return SetIfaceFlags( name, IFF_LINK1, fib );
}
#endif

int SetIfaceAddr( const std::string &name, const std::string &addr_string, size_t fib ) {
    int rc = SetIfaceAddrField( name, SIOCSIFADDR, addr_string, fib );
    if (rc) {
        logger.e( "SIOCSIFADDR: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Address setting succeeded, name: %s.", name.c_str() );
    return 0;
}

#ifdef __QNXNTO__
int DelIfaceAddr( const std::string &name, size_t fib ) {
    int rc = SetIfaceAddrField( name, SIOCDIFADDR, "", fib );
    if (rc) {
        logger.e( "SIOCDIFADDR: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Address deleted, interface name: %s.", name.c_str() );
    return 0;
}
#endif

int SetIfaceNetPrefixLen( const std::string &name, size_t len, size_t fib ) {
    if (len>BITS_IN_IPV4ADDR) {
        return EINVAL;
    }
    struct sockaddr_in sa{};
#ifdef __QNXNTO__
    sa.sin_len = sizeof sa;
#else
    sa.sin_family = AF_INET;
#endif
    sa.sin_addr.s_addr = htonl( 0xFFFFFFFF << (BITS_IN_IPV4ADDR-len) );
    int rc = SetIfaceAddrField( name, SIOCSIFNETMASK, sa, fib );
    if (rc) {
        logger.e( "SIOCSIFNETMASK: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Mask setting succeeded, interface name: %s.", name.c_str() );
    return 0;
}


int SetIfaceDstAddr( const std::string &name, const std::string &addr_string, size_t fib ) {
    int rc = SetIfaceAddrField( name, SIOCSIFDSTADDR, addr_string, fib );
    if (rc) {
        logger.e( "SIOCSIFDSTADDR: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "Dst address setting succeeded, interface name: %s.", name.c_str() );
    return 0;
}


#ifdef __QNXNTO__
int SetGreSA( const std::string &name, const std::string &addr_string, size_t fib ) {
    int rc = SetIfaceAddrField( name, GRESADDRS, addr_string, fib );
    if (rc) {
        logger.e( "GRESADDRS: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "GRE SA setting succeeded, interface name: %s.", name.c_str() );
    return 0;
}
#else
int SetGreSA( __attribute__((unused)) const std::string &name,
              __attribute__((unused)) const std::string &addr_string,
              __attribute__((unused)) size_t fib ) {
    return ENOTSUP;
}
#endif


#ifdef __QNXNTO__
int SetGreDA( const std::string &name, const std::string &addr_string, size_t fib ) {
    int rc = SetIfaceAddrField( name, GRESADDRD, addr_string, fib );
    if (rc) {
        logger.e( "GRESADDRD: errno=%d", rc );
        return rc;
    }

    loggerSp.i( "GRE DA setting succeeded, interface name: %s.", name.c_str() );
    return 0;
}
#else
int SetGreDA( __attribute__((unused)) const std::string &name,
              __attribute__((unused)) const std::string &addr_string,
              __attribute__((unused)) size_t fib ) {
    return ENOTSUP;
}
#endif

#ifdef __QNXNTO__
int AddDefRoute( const std::string &gateway, __attribute__((unused)) size_t fib ) {
    int rc=0;
    struct RtMsg rtmsg{};
    struct rt_msghdr *const rtm = &rtmsg.rt;
    rtm->rtm_type = RTM_ADD;
    rc = PerformRoutingOps(&rtmsg, gateway, fib);
    if (!rc) {
        return EOK;
    } else {
        logger.e( "Default route add failed." );
        return rc;
    }
}
#else
int AddDefRoute( __attribute__((unused)) const std::string &gateway,
                 __attribute__((unused)) size_t fib ) {
    return ENOTSUP;
}
#endif


#ifdef __QNXNTO__
int DelDefRoute( const std::string &gateway, size_t fib ) {
    int rc=0;
    struct RtMsg rtmsg{};
    struct rt_msghdr *const rtm = &rtmsg.rt;
    rtm->rtm_type = RTM_DELETE;
    rc = PerformRoutingOps(&rtmsg, gateway, fib);
    if (!rc) {
        return EOK;
    } else {
        logger.e( "Default route delete failed." );
        return rc;
    }
}
#else
int DelDefRoute( __attribute__((unused)) const std::string &gateway,
                 __attribute__((unused)) size_t fib ) {
    return ENOTSUP;
}
#endif

}
}
