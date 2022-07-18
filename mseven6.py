# SPDX-License-Identifier: GPL-2.0+

from impacket.dcerpc.v5 import transport, even6, dtypes
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from . import mseven6ext


class EvtRpcQuerySeekFixed(even6.EvtRpcQuerySeek):
    structure = (
        ('LogQuery', even6.CONTEXT_HANDLE_LOG_QUERY),
        ('Pos', dtypes.LARGE_INTEGER),
        ('BookmarkXML', dtypes.LPWSTR),
        ('TimeOut', dtypes.DWORD),  # нет в even6.EvtRpcQuerySeek
        ('Flags', dtypes.DWORD),
    )


class EvtRpcQuerySeekFixedResponse(even6.EvtRpcQuerySeekResponse):
    pass


even6.OPNUMS[12] = (EvtRpcQuerySeekFixed, EvtRpcQuerySeekFixedResponse)


class Result:
    def __init__(self, conn, handle):
        self._conn = conn
        self._handle = handle

    def __iter__(self):
        self._resp = None
        return self

    def __next__(self):
        if self._resp != None and self._resp['NumActualRecords'] == 0:
            return None

        if self._resp == None or self._index == self._resp['NumActualRecords']:
            req = even6.EvtRpcQueryNext()
            req['LogQuery'] = self._handle
            req['NumRequestedRecords'] = 20
            req['TimeOutEnd'] = 1000
            req['Flags'] = 0
            self._resp = self._conn.dce.request(req)

            if self._resp['NumActualRecords'] == 0:
                raise StopIteration
            else:
                self._index = 0

        offset = self._resp['EventDataIndices'][self._index]['Data']
        size = self._resp['EventDataSizes'][self._index]['Data']
        self._index += 1

        return b''.join(self._resp['ResultBuffer'][offset:offset + size])

class MSEven6:
    def __init__(self, machine, username, password, domain):
        binding = hept_map(machine, even6.MSRPC_UUID_EVEN6, protocol='ncacn_ip_tcp')

        trans = transport.DCERPCTransportFactory(binding)
        trans.set_credentials(username, password, domain)

        self.dce = trans.get_dce_rpc()
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    def connect(self):
        self.dce.connect()
        self.dce.bind(even6.MSRPC_UUID_EVEN6)
        self.demo()

    def query(self, path, query):
        req = even6.EvtRpcRegisterLogQuery()
        req['Path'] = path + '\x00'
        req['Query'] = query + '\x00'
        req['Flags'] = even6.EvtQueryChannelName | even6.EvtReadOldestToNewest

        resp = self.dce.request(req)
        handle = resp['Handle']

        return Result(self, handle)

    def demo(self):
        # req = mseven6ext.EvtRpcGetPublisherListForChannel()
        # req['ChannelName'] = path + '\x00'
        # req['Flags'] = 0
        # resp = self.dce.request(req)
        # if resp['Error'] != 0:
        #     print(f"Error: {resp['Error']}")
        # else:
        #     for pub in resp['PublisherIds']:
        #         print(pub['Data'])

        req = mseven6ext.EvtRpcGetPublisherMetadata()
        req['PublisherId'] = 'PowerShell\x00'
        req['LogFilePath'] = 'Windows PowerShell\x00'
        req['Locale'] = 1033  # en-US
        req['Flags'] = 0
        resp = self.dce.request(req)
        for i, prop in enumerate(resp['PubMetadataProps']['Props']):
            print(i, ": ", prop['Type'])
        # with open("raw_resp.bin", "wb") as fd:
            # fd.write(resp["Raw"])
        handle = resp['Other'][-24:-4]

        event = mseven6ext.EventDescriptor()
        event['Id'] = 400
        event['Version'] = 0
        event['Channel'] = 0
        event['Level'] = 4
        event['Opcode'] = 0
        event['Task'] = 0
        event['Keyword'] = 0x8000000000000000
        rawEvent = event.getData()

        values = mseven6ext.EvtRpcVariantList()
        values['Count'] = 0
        values['Props'] = mseven6ext.EvtRpcVariantList.PArray()

        req = mseven6ext.EvtRpcMessageRender()
        req['PubMetadataHandle'] = handle
        req['SizeEventId'] = len(rawEvent)
        req['EventId'] = rawEvent
        req['MessageId'] = 0
        req['Values'] = values
        req['Flags'] = 0x00000002
        req['MaxSizeString'] = 1024
        resp = self.dce.request(req)
        print(resp['ActualSizeString'])
