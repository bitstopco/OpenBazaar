from random import randint
import re
import socket
import struct
import stun


def check_NAT_status():
    # list of additional stun servers taken (and tested) from natvpn project
    # https://code.google.com/p/natvpn/source/browse/trunk/stun_server_list
    # removed those that didn't ping back.
    stun.stun_servers_list = stun.stun_servers_list + ('stun.l.google.com',
                                                       'stun1.l.google.com',
                                                       'stun2.l.google.com',
                                                       'stun3.l.google.com',
                                                       'stun4.l.google.com',
                                                       'stun.ekiga.net',
                                                       'stun.ideasip.com',
                                                       'stun.iptel.org',
                                                       'stun.schlund.de',
                                                       'stunserver.org',
                                                       'stun.voiparound.com',
                                                       'stun.voipbuster.com',
                                                       'stun.voipstunt.com',
                                                       'stun.voxgratia.org',
                                                       'stun.xten.com')

    nat_type, external_ip, external_port = stun.get_ip_info()
    return {'nat_type': nat_type,
            'external_ip': external_ip,
            'external_port': external_port}


def is_local_tcp_port_listening(port):
    r = -1
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        r = s.connect_ex(('127.0.01', port))
        s.close()
    except:
        pass
    return r == 0


def get_random_free_tcp_port(min_port_number=1025, max_port_number=49151):
    while True:
        port = randint(min_port_number, max_port_number)
        print "Checking if port", port, "is free ..."
        if not is_local_tcp_port_listening(port):
            print "Port", port, "is free!"
            return port


def is_loopback_addr(addr):
    return addr.startswith("127.0.0.") or addr == 'localhost'


def is_valid_port(port):
    return 0 < int(port) <= 65535


def is_valid_protocol(protocol):
    return protocol == 'tcp'


def is_valid_ip_address(addr):
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False


def is_private_ip_address(addr):
    if is_loopback_addr(addr):
        return True
    if not is_valid_ip_address(addr):
        return False
    # http://stackoverflow.com/questions/691045/how-do-you-determine-if-an-ip-address-is-private-in-python
    f = struct.unpack('!I', socket.inet_pton(socket.AF_INET, addr))[0]
    private = (
        # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [2130706432, 4278190080],
        # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [3232235520, 4294901760],
        # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [2886729728, 4293918720],
        # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
        [167772160, 4278190080],
    )
    for net in private:
        if f & net[1] == net[0]:
            return True
    return False


def uri_parts(uri):
    m = re.match(r"(\w+)://([\w\.]+):(\d+)", uri)
    if m is not None:
        return m.group(1), m.group(2), m.group(3)
    else:
        raise RuntimeError('URI is not valid')
