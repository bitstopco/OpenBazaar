#!./env/bin/python
# OpenBazaar's launcher script.
import argparse
import os
from network_util import init_aditional_STUN_servers, check_NAT_status


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


def getDefaults():
    return {'SERVER_PORT': 12345,
            'LOG_DIR': 'logs',
            'LOG_FILE': 'production.log',
            'DB_DIR': 'db',
            'DB_FILE': 'ob.db',
            'DEVELOPMENT': False,
            'SEED_MODE': False,
            'SEED_HOSTNAMES': 'seed.openbazaar.org seed2.openbazaar.org seed.openlabs.co us.seed.bizarre.company eu.seed.bizarre.company'.split(),
            'DISABLE_UPNP': False,
            'DISABLE_OPEN_DEFAULT_WEBBROWSER': False,
            'LOG_LEVEL': 10,  # CRITICAL=50, ERROR=40, WARNING=30, DEBUG=10, NOTSET=0
            'NODES': 3,
            'HTTP_IP': '127.0.0.1',
            'HTTP_PORT': -1,
            'BITMESSAGE_USER': None,
            'BITMESSAGE_PASS': None,
            'BITMESSAGE_PORT': -1,
            'ENABLE_IP_CHECKER': False,
            'CONFIG_FILE': None
            }


def initArgumentParser(defaults):

    parser = argparse.ArgumentParser(usage=usage())

    parser.add_argument('-i', '--server-public-ip', help='Server Public IP')

    parser.add_argument('-p', '--server-public-port', '--my-market-port',
                        default=defaults['SERVER_PORT'],
                        type=int,
                        help='Server Public Port (default 12345)')

    parser.add_argument('-k', '--http-ip', '--web-ip',
                        default=defaults['HTTP_IP'],
                        help='Web Interface IP (default 127.0.0.1;' +
                        ' use 0.0.0.0 for any)')

    parser.add_argument('-q', '--web-port', '--http-port',
                        type=int, default=defaults['HTTP_PORT'],
                        help='Web Interface Port (default random)')

    parser.add_argument('-l', '--log',
                        default=defaults['LOG_DIR'] + os.sep + defaults['LOG_FILE'],
                        help='Log File Path')

    parser.add_argument('--log-level',
                        default=defaults['LOG_LEVEL'],
                        help='Log Level (Default: 10 - DEBUG')

    parser.add_argument('-d', '--development-mode',
                        action='store_true',
                        help='Development mode')

    parser.add_argument("--db-path", "--database",
                        default=defaults['DB_DIR'] + os.sep + defaults['DB_FILE'],
                        help="Database filename")

    parser.add_argument('-n', '--dev-nodes',
                        type=int,
                        help='Number of Dev nodes to start up')

    parser.add_argument('--bitmessage-user', '--bmuser',
                        default=defaults['BITMESSAGE_USER'],
                        help='Bitmessage API username')

    parser.add_argument('--bitmessage-pass', '--bmpass',
                        default=defaults['BITMESSAGE_PASS'],
                        help='Bitmessage API password')

    parser.add_argument('--bitmessage-port', '--bmport',
                        type=int,
                        default=defaults['BITMESSAGE_PORT'],
                        help='Bitmessage API port (eg: 8444)')

    parser.add_argument('-u', '--market-id',
                        help='Market ID')

    parser.add_argument('-j', '--disable-upnp',
                        action='store_true',
                        default=defaults['DISABLE_UPNP'],
                        help='Disable automatic UPnP port mappings')

    parser.add_argument('-S', '--seed-mode',
                        action='store_true',
                        default=defaults['SEED_MODE'],
                        help='Enable Seed Mode')

    parser.add_argument('-s', '--seeds',
                        nargs='*',
                        default=[])

    parser.add_argument('--disable-open-browser',
                        action='store_true',
                        default=defaults['DISABLE_OPEN_DEFAULT_WEBBROWSER'],
                        help='Don\'t open preferred web browser ' +
                        'automatically on start')

    parser.add_argument('--config-file',
                        default=defaults['CONFIG_FILE'],
                        help='Disk path to an OpenBazaar configuration file')

    parser.add_argument('--enable-ip-checker',
                        default=defaults['ENABLE_IP_CHECKER'])

    parser.add_argument('command')
    return parser


def usage():
    return """
openbazaar [options] <command>

    COMMANDS
        start            Start OpenBazaar
        stop             Stop OpenBazaar

    OPTIONS
    -i, --server-public-ip <ip address>
        Server public IP

    -p, --server-public-port, --my-market-port <port number>
        Server public (P2P) port (default 12345)

    -k, --http-ip, --web-ip <ip address>
        Web interface IP (default 127.0.0.1; use 0.0.0.0 for any)

    -q, --web-port, --http-port <port number>
        Web interface port (-1 = random by default)

    -l, --log <file path>
        Log file path (default 'logs/production.log')

    --log-level <level>
        Log verbosity level (default: 10 - DEBUG)
        Expected <level> values are:
           0 - NOT SET
          10 - DEBUG
          20 - INFO
          30 - WARNING
          40 - ERROR
          50 - CRITICAL

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

    --enable-ip-checker
        Enable periodic IP address checking. In case you expect your IP to change rapidly.

"""


def start(arguments, defaults):
    """
    """
    print "Checking NAT Status..."
    init_aditional_STUN_servers()
    nat_status = check_NAT_status()

    # TODO: if a --config file has been specified
    # first load config values from it
    # then override the rest that has been passed
    # through the command line.

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
        # a non symmetric nat (e.g. Full Cone, Restricted Cone)
        # learn more: http://think-like-a-computer.com/2011/09/16/types-of-nat/
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

    # log path
    log_path = defaults['LOG_DIR'] + os.sep + defaults['LOG_FILE']
    if arguments.log is not None and arguments.log != log_path:
        log_path = arguments.log

    # log level
    log_level = defaults['LOG_LEVEL']
    if arguments.log_level is not None and arguments.log_level != log_level:
        log_level = arguments.log_level

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

    # database
    if not os.path.exists(defaults['DB_DIR']):
        os.makedirs(defaults['DB_DIR'], 0755)

    db_path = defaults['DB_DIR'] + os.sep + defaults['DB_FILE']
    if arguments.db_path != db_path:
        db_path = arguments.db_path

    # disable upnp
    disable_upnp = defaults['DISABLE_UPNP']
    if arguments.disable_upnp:
        disable_upnp = True

    # disable open browser
    disable_open_browser = defaults['DISABLE_OPEN_DEFAULT_WEBBROWSER']
    if arguments.disable_open_browser:
        disable_open_browser = True

    # enable ip checker
    enable_ip_checker = defaults['ENABLE_IP_CHECKER']
    if arguments.enable_ip_checker:
        enable_ip_checker = True

    import openbazaar_daemon
    from threading import Thread
    ob_ctx = openbazaar_daemon.OpenBazaarContext(nat_status,
                                                 my_market_ip,
                                                 my_market_port,
                                                 http_ip,
                                                 http_port,
                                                 db_path,
                                                 log_path,
                                                 log_level,
                                                 market_id,
                                                 bm_user,
                                                 bm_pass,
                                                 bm_port,
                                                 seed_peers,
                                                 seed_mode,
                                                 dev_mode,
                                                 disable_upnp,
                                                 disable_open_browser,
                                                 enable_ip_checker)

    print "Arguments:"
    print arguments

    print "\nOpenBazaarContextObject:"
    print ob_ctx

    ob_daemon_thread = Thread(target=openbazaar_daemon.start_node,
                              name='openbazaar_daemon_thread',
                              args=(ob_ctx))
    ob_daemon_thread.daemon = True
    ob_daemon_thread.start()
    # openbazaar_daemon.start_node(ob_ctx)

if __name__ == '__main__':
    defaults = getDefaults()
    parser = initArgumentParser(defaults)
    arguments = parser.parse_args()

    if is_osx():
        osx_check_dyld_library_path()

    print "Command:", arguments.command

    if arguments.command == 'start':
        start(arguments, defaults)
    elif arguments.command == 'stop':
        pass
    elif arguments.command == 'status':
        pass
