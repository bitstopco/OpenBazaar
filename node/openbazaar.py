#!./env/bin/python
# OpenBazaar's launcher script.
import argparse
import os
from network_util import check_NAT_status


def is_osx():
    return os.uname()[0].startswith('Darwin')


def osx_check_dyld_library_path():
    '''This is a necessary workaround as you cannot set the DYLD_LIBRARY_PATH by the time python has started.'''
    if 'DYLD_LIBRARY_PATH' not in os.environ or len(os.environ['DYLD_LIBRARY_PATH']) == 0:
        print 'WARNING: DYLD_LIBRARY_PATH not set, this might cause issues with openssl elliptic curve cryptography and other libraries.'
        print "It is recommended that you stop OpenBazaar and set your DYLD_LIBRARY_PATH environment variable as follows\n"
        print 'export DYLD_LIBRARY_PATH=$(brew --prefix openssl)/lib:${DYLD_LIBRARY_PATH}', "\n"
        print 'then restart OpenBazaar.', "\n"

        from ctypes import cdll
        try:
            print "Attempting to load libcrypto.dylib and libssl.dylib."
            openssl_prefix = os.popen('brew --prefix openssl')
            if openssl_prefix is not None:
                cdll.LoadLibrary(openssl_prefix + '/lib/libcrypto.dylib')
                cdll.LoadLibrary(openssl_prefix + '/lib/libssl.dylib')
                print "Attempting to load libcrypto.dylib and libssl.dylib."
        except:
            pass


def initArgumentParser():
    parser = argparse.ArgumentParser(usage=usage())

    parser.add_argument('-i', '--server-public-ip', help='Server Public IP')

    parser.add_argument('-p', '--server-public-port', '--my-market-port',
                        default=12345,
                        type=int,
                        help='Server Public Port (default 12345)')

    parser.add_argument('-k', '--http-ip', '--web-ip',
                        default='127.0.0.1',
                        help='Web Interface IP (default 127.0.0.1;' +
                        ' use 0.0.0.0 for any)')

    parser.add_argument('-q', '--web-port', '--http-port',
                        type=int, default=-1,
                        help='Web Interface Port (default random)')

    parser.add_argument('-l', '--log',
                        default='logs/production.log',
                        help='Log File')

    parser.add_argument('-d', '--development-mode', action='store_true',
                        help='Development mode')

    parser.add_argument("--database",
                        default='db/ob.db',
                        help="Database filename")

    parser.add_argument('-n', '--dev-nodes',
                        type=int,
                        help='Number of Dev nodes to start up')

    parser.add_argument('--bitmessage-user', '--bmuser',
                        default='username',
                        help='Bitmessage API username')

    parser.add_argument('--bitmessage-pass', '--bmpass',
                        default='password',
                        help='Bitmessage API password')

    parser.add_argument('--bitmessage-port', '--bmport',
                        type=int,
                        default=8442,
                        help='Bitmessage API port')

    parser.add_argument('-u', '--market-id',
                        help='Market ID')

    parser.add_argument('-j', '--disable-upnp',
                        action='store_true',
                        default=False,
                        help='Disable automatic UPnP port mappings')

    parser.add_argument('-S', '--seed-mode',
                        action='store_true',
                        default=False,
                        help='Enable Seed Mode')

    parser.add_argument('-s', '--seeds',
                        nargs='*',
                        default=[])
    parser.add_argument('--disable-open-browser',
                        action='store_true',
                        default=False,
                        help='Don\'t open preferred web browser ' +
                        'automatically on start')
    parser.add_argument('--config-file',
                        default=None,
                        help='Disk path to an OpenBazaar configuration file')

    parser.add_argument('command')
    return parser


def getDefaults():
    return {'SERVER_PORT': 12345,
            'LOG_DIR': 'logs',
            'LOG_FILE': 'production.log',
            'DB_DIR': 'db',
            'DB_FILE': 'ob.db',
            'DEVELOPMENT': False,
            'SEED_HOSTNAMES': 'seed.openbazaar.org seed2.openbazaar.org seed.openlabs.co us.seed.bizarre.company eu.seed.bizarre.company'.split(),
            'DISABLE_UPNP': False,
            'DISABLE_OPEN_DEFAULT_WEBBROWSER': False,
            'LOG_LEVEL': 10,  # CRITICAL=50, ERROR=40, WARNING=30, DEBUG=10, NOTSET=0
            'NODES': 3,
            'HTTP_IP': '127.0.0.1',
            'HTTP_PORT': -1,
            'BITMESSAGE_USER': 'username',
            'BITMESSAGE_PASS': 'password',
            'BITMESSAGE_PORT': 8442
            }


def usage():
    return """
openbazaar [options] <command>

    COMMANDS
        start            Start OpenBazaar
        stop             Stop OpenBazaar

    OPTIONS
    -i, --server-public-ip
        Server public IP

    -p, --server-public-port, --my-market-port
        Server public (P2P) port (default 12345)

    -k, --http-ip, --web-ip
        Web interface IP (default 127.0.0.1; use 0.0.0.0 for any)

    -q, --web-port, --http-port
        Web interface port (random by default)

    -l, --log
        Log file (default 'logs/production.log')

    -d, --development-mode
        Enable development mode

    --database
        Database filename. (default 'db/od.db')

    -n, --dev-nodes
        Number of dev nodes to start up

    --bitmessage-user, --bmuser
        Bitmessage API username

    --bitmessage-pass, --bmpass
        Bitmessage API password

    --bitmessage-port, --bmport
        Bitmessage API port

    -u, --market-id
        Market ID

    -j, --disable-upnp
        Disable automatic UPnP port mappings

    -S, --seed-mode
        Enable seed mode

    --disable-open-browser
        Don't open preferred web browser automatically on start

    --config-file
        Disk path to an OpenBazaar configuration file



"""


def start(arguments, defaults):
    print "Checking NAT Status..."
    nat_status = check_NAT_status()

    # TODO: if a --config file has been specified
    # first load config values from it
    # then override the rest that has been passed
    # through the command line.

    # market ip
    print arguments
    my_market_ip = ''
    if arguments.server_public_ip is not None:
        my_market_ip = arguments.server_public_ip
    else:
        print nat_status
        my_market_ip = nat_status['external_ip']

    # market port
    my_market_port = defaults['SERVER_PORT']
    if arguments.server_public_port is not None and arguments.server_public_port != my_market_port:
        my_market_port = arguments.server_public_port
    else:
        import stun
        # let's try the external port if we're behind
        # a non symmetric nat
        print stun.SymmetricNAT
        print stun.SymmetricUDPFirewall
        if nat_status['nat_type'] not in (stun.SymmetricNAT,
                                          stun.SymmetricUDPFirewall):
            my_market_port = nat_status['external_port']

    # http ip
    http_ip = defaults['HTTP_IP']
    if arguments.http_ip is not None:
        http_ip = arguments.http_ip

    # http port
    http_port = defaults['HTTP_PORT']
    if arguments.web_port is not None and arguments.web_port != http_port:
        http_port = arguments.web_port

    # create default LOG_DIR if not present
    if not os.path.exists(defaults['LOG_DIR']):
        os.makedirs(defaults['LOG_DIR'], 0755)

    # log file
    log_path = defaults['LOG_DIR'] + os.sep + defaults['LOG_FILE']
    if arguments.log is not None and arguments.log != log_path:
        log_path = arguments.log

    # market id
    market_id = None
    if arguments.market_id is not None:
        market_id = arguments.market_id

    # bm user
    bm_user = defaults['BITMESSAGE_USER']
    if arguments.bitmessage_user is not None and arguments.bitmessage_user != bm_user:
        bm_user = arguments.bitmessage_user

    # bm pass
    bm_pass = defaults['BITMESSAGE_PASS']
    if arguments.bitmessage_pass is not None and arguments.bitmessage_pass != bm_pass:
        bm_pass = arguments.bitmessage_pass

    # bm port
    bm_port = defaults['BITMESSAGE_PORT']
    if arguments.bitmessage_port is not None and arguments.bitmessage_port != bm_port:
        bm_port = arguments.bitmessage_port

    # seed_peers
    seed_peers = defaults['SEED_HOSTNAMES']
    if len(arguments.seeds) > 0:
        seed_peers = seed_peers + arguments.seeds

    # seed_mode
    seed_mode = False
    if arguments.seed_mode:
        seed_mode = True

    # dev_mode
    dev_mode = defaults['DEVELOPMENT']
    if arguments.development_mode != dev_mode:
        dev_mode = arguments.development_mode

    # log level
    log_level = defaults['LOG_LEVEL']

    # database
    if not os.path.exists(defaults['DB_DIR']):
        os.makedirs(defaults['DB_DIR'], 0755)

    database = defaults['DB_DIR'] + os.sep + defaults['DB_FILE']
    if arguments.database != database:
        database = arguments.database

    # disable upnp
    disable_upnp = defaults['DISABLE_UPNP']
    if arguments.disable_upnp:
        disable_upnp = True

    # disable open browser
    disable_open_browser = defaults['DISABLE_OPEN_DEFAULT_WEBBROWSER']
    if arguments.disable_open_browser:
        disable_open_browser = True

    print "my_market_ip", my_market_ip
    print "my_market_port", my_market_port
    print "http_ip", http_ip
    print "http_port", http_port
    print "log_path", log_path
    print "market_id", market_id
    print "bm_user", bm_user,
    print "bm_pass", bm_pass,
    print "bm_port", bm_port,
    print "seed_peers", seed_peers
    print "seed_mode", seed_mode
    print "dev_mode", dev_mode
    print "log_level", log_level
    print "database", database
    print "disable_upnp", disable_upnp
    print "disable_open_browser", disable_open_browser

    import openbazaar_daemon
    openbazaar_daemon.start_node(my_market_ip,
                                 my_market_port,
                                 http_ip,
                                 http_port,
                                 log_path,
                                 market_id,
                                 bm_user,
                                 bm_pass,
                                 bm_port,
                                 seed_peers,
                                 seed_mode,
                                 dev_mode,
                                 log_level,
                                 database,
                                 disable_upnp,
                                 disable_open_browser,
                                 nat_status)


if __name__ == '__main__':

    parser = initArgumentParser()
    arguments = parser.parse_args()

    if is_osx():
        osx_check_dyld_library_path()

    defaults = getDefaults()
    print "Command:", arguments.command
    if arguments.command == 'start':
        start(arguments, defaults)
    elif arguments.command == 'stop':
        pass
    elif arguments.command == 'status':
        pass