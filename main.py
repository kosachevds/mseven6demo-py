import codecs
import sys
from datetime import datetime

from impacket.dcerpc.v5 import dtypes, epm, even6, ndr, rpcrt, transport

from binxml import ResultSet
import mseven6ext

_IFACE_UUID = even6.MSRPC_UUID_EVEN6
_EVT_SEEK_RELATIVE_TO_FIRST = 0x00000001

_DOMAIN = "."
_BATCH_SIZE = 31
_EPS_WRITE_INTERVAL_SEC = 2
_MAX_EVENTS = 1000


def main():
    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    channel = sys.argv[4]
    rendering = False
    if len(sys.argv) > 5:
        rendering = strtobool(sys.argv[5])

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
    start = datetime.now()
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
            events.append(ResultSet(event).xml())
            if rendering:
                RenderMessageDefault(dce)
    stop = datetime.now()
    print("EPS: ", len(events) / (stop - start).total_seconds())

    with codecs.open("data/events.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(events))


def RenderMessageDefault(dce):
    render_flags = {
        'level': 0x00000002,
        'task': 0x00000003,
        'opcode': 0x00000004,
    }
    event = mseven6ext.EventDescriptor()
    event['Id'] = 903
    event['Version'] = 0
    event['Channel'] = 0
    event['Level'] = 0
    event['Opcode'] = 0
    event['Task'] = 0
    event['Keyword'] = 0x0080000000000000

    event_id = ndr.NDRUniConformantArray()
    event_id['Data'] = event.getData()

    result = {}
    errors = {}
    for name, flag in render_flags.items():
        try:
            result[name] = render_message(dce, event_id, flag)
        except even6.DCERPCSessionError as err:
            errors[name] = err
    error = ""
    if len(errors) > 0:
        if len(errors) == len(render_flags):
            # любая из ошибок
            raise next(iter(errors.values()))
        error = "; ".join(f"{f}: {err}" for f, err in errors.items())


def render_message(dce, event_id_bin, flags):
    req = mseven6ext.EvtRpcMessageRenderDefault()
    req['SizeEventId'] = len(event_id_bin)
    req['EventId'] = event_id_bin
    req['MessageId'] = 0xffffffff  # -1
    req['Values'] = mseven6ext.EvtRpcVariantList()
    req['Flags'] = flags
    req['MaxSizeString'] = 1024
    dce_resp = dce.request(req)
    err_code = dce_resp['Error']['Error']
    if err_code != 0:
        raise even6.DCERPCSessionError(error_code=err_code)
    raw_text = b''.join(dce_resp['String'])
    return raw_text.decode('utf-16').strip("\x00")


def strtobool(val):
    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return True
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return False
    else:
        raise ValueError("invalid truth value %r" % (val,))


if __name__ == "__main__":
    main()
