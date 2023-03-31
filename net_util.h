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

namespace fnv {
namespace vnm {

    std::string GetIfAddress( const std::string &ifnm, size_t fibno=0 );
    std::string FindIfName( const std::string &ipaddr, size_t fibno );
    size_t VlanIdFromV4Address( const std::string &ipaddr );
    size_t Ipv4AddrFromBits( size_t prefix, size_t prefixlen, size_t subnetno, size_t subnetlen, size_t hostno );
    int Ipv4Prefixlen2Mask( int prefix, uint32_t &mask);
    bool Ipv4AddrFromString( const std::string &ip_string, struct in_addr &addr );
    std::string StringFromIpv4Addr( size_t ipaddr );
    bool ValidateIpv4Address( const std::string &ipaddr );
    bool ValidateIfname( const std::string &ifnm );
    int CreateCloneIface( const std::string &name, size_t fib=0 );
    int DestroyCloneIface( const std::string &name, size_t fib=0 );
    int CreateVlanIface( const std::string &parent, size_t vlanid );
    int DeleteVlanIface( const std::string &name );
    int SetIfaceMtu( const std::string &name, size_t mtu, size_t fib=0 );
    int SetIfaceFib( const std::string &name, size_t fib );
    int DeleteTunnel( const std::string &name, size_t fib=0 );
    int SetIfaceLink1Flag( const std::string &name, size_t fib=0 );
    int GetIfaceFlags( const std::string &name, unsigned long &flags, size_t fib=0 );
    int SetIfaceAddr( const std::string &name, const std::string &addr_string, size_t fib=0 );
    int DelIfaceAddr( const std::string &name, size_t fib=0 );
    int SetIfaceNetPrefixLen( const std::string &name, size_t len, size_t fib=0 );
    int SetIfaceDstAddr( const std::string &name, const std::string &addr_string, size_t fib=0 );
    int SetGreSA( const std::string &name, const std::string &addr_string, size_t fib=0 );
    int SetGreDA( const std::string &name, const std::string &addr_string, size_t fib=0 );
    int SetIfaceVlan( const std::string &name, const std::string &parentifnm, int id, size_t fib=0 );
    int AddDefRoute( const std::string &gateway, size_t fib=0 );
    int DelDefRoute( const std::string &gateway, size_t fib=0 );

} // vnm
} // fnv
