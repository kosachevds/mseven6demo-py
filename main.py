import uuid
from impacket.dcerpc.v5 import epm, even6, transport, dtypes, rpcrt, ndr

from binxml import ResultSet
import mseven6ext

_IFACE_UUID = even6.MSRPC_UUID_EVEN6
_EVT_SEEK_RELATIVE_TO_FIRST = 0x00000001

_HOST = "172.30.254.52"
_USERNAME = "user"
_PASSWORD = "ms-even6"
_DOMAIN = ""
_CHANNEL = "Application"


def main():
    string_binding = epm.hept_map(_HOST, _IFACE_UUID, protocol="ncacn_ip_tcp")
    rpc_transport = transport.DCERPCTransportFactory(string_binding)
    rpc_transport.set_credentials(_USERNAME, _PASSWORD, _DOMAIN)
    dce = rpc_transport.get_dce_rpc()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(_IFACE_UUID)

    req = mseven6ext.EvtRpcGetPublisherMetadata()
    req['PublisherId'] = 'PowerShell\x00'
    req['LogFilePath'] = 'Windows PowerShell\x00'
    req['Locale'] = 1033  # en-US
    req['Flags'] = 0
    resp = dce.request(req)
    handle = resp['PubMetadata']
    print(uuid.UUID(bytes=handle[4:]))

    event = mseven6ext.EventDescriptor()
    event['Id'] = 400
    event['Version'] = 0
    event['Channel'] = 0
    event['Level'] = 4
    event['Opcode'] = 0
    event['Task'] = 0
    event['Keyword'] = 0x8000000000000000
    raw_event = event.getData()

    event_id = ndr.NDRUniConformantArray()
    event_id['MaximumCount'] = len(raw_event)
    event_id['Data'] = raw_event

    values = mseven6ext.EvtRpcVariantList()
    values['Count'] = 0
    values['Props'] = mseven6ext.EvtRpcVariantList.PArray()

    req = mseven6ext.EvtRpcMessageRender()
    req['PubMetadataHandle'] = handle
    req['SizeEventId'] = len(raw_event)
    req['EventId'] = event_id
    req['MessageId'] = 0
    req['Values'] = values
    req['Flags'] = 0x00000002
    req['MaxSizeString'] = 1024
    resp = dce.request(req)
    print(resp['ActualSizeString'])


if __name__ == "__main__":
    main()
