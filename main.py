import codecs
import sys
from datetime import datetime

from impacket.dcerpc.v5 import dtypes, epm, even6, ndr, rpcrt, transport

from binxml import ResultSet

_IFACE_UUID = even6.MSRPC_UUID_EVEN6
_EVT_SEEK_RELATIVE_TO_FIRST = 0x00000001

_DOMAIN = "."
_BATCH_SIZE = 31
_EPS_WRITE_INTERVAL_SEC = 2
_MAX_EVENTS = 10000


def main():
    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    channel = sys.argv[4]

    string_binding = epm.hept_map(host, _IFACE_UUID, protocol="ncacn_ip_tcp")
    rpc_transport = transport.DCERPCTransportFactory(string_binding)
    rpc_transport.set_credentials(username, password, _DOMAIN)
    dce = rpc_transport.get_dce_rpc()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(_IFACE_UUID)

    request = even6.EvtRpcRegisterLogQuery()
    request['Path'] = channel + '\x00'
    request['Query'] = "*" + '\x00'
    request['Flags'] = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest

    resp = dce.request(request)
    log_handle = resp['Handle']

    events = []
    while len(events) <= _MAX_EVENTS:
        request = even6.EvtRpcQueryNext()
        request['LogQuery'] = log_handle
        request['NumRequestedRecords'] = _BATCH_SIZE
        request['TimeOutEnd'] = 1000
        request['Flags'] = 0
        resp = dce.request(request)
        num_records = resp['NumActualRecords']
        if num_records == 0:
            break
        for i in range(num_records):
            event_offset = resp['EventDataIndices'][i]['Data']
            event_size = resp['EventDataSizes'][i]['Data']
            event = resp['ResultBuffer'][event_offset:event_offset + event_size]
            event_bytes = b''.join(event)
            events.append(ResultSet(event_bytes).xml())

    with codecs.open("data/events.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(events))


if __name__ == "__main__":
    main()
