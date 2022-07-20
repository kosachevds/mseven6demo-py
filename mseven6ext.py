from impacket.dcerpc.v5 import even6, dtypes, ndr, enum

LCID = dtypes.DWORD


class DCERPCSessionError(even6.DCERPCSessionError):
    pass


class EventDescriptor(ndr.NDRSTRUCT):
    structure = (
        ('Id', dtypes.USHORT),
        ('Version', dtypes.UCHAR),
        ('Channel', dtypes.UCHAR),
        ('Level', dtypes.UCHAR),
        ('Opcode', dtypes.UCHAR),
        ('Task', dtypes.USHORT),
        ('Keyword', dtypes.ULONGLONG),
    )


class BooleanArray(ndr.NDRSTRUCT):
    class PArray(ndr.NDRPOINTER):
        class Array(ndr.NDRUniConformantArray):
            item = dtypes.BOOLEAN

        referent = (
            ('Data', Array),
        )

    structure = (
        ('Count', dtypes.DWORD),
        ('Ptr', PArray),
    )


class UInt32Array(ndr.NDRSTRUCT):
    class PArray(ndr.NDRPOINTER):
        class Array(ndr.NDRUniConformantArray):
            item = dtypes.ULONG

        referent = (
            ('Data', Array),
        )

    structure = (
        ('Count', dtypes.DWORD),
        ('Ptr', PArray),
    )


class UInt64Array(ndr.NDRSTRUCT):
    class PArray(ndr.NDRPOINTER):
        class Array(ndr.NDRUniConformantArray):
            item = dtypes.ULONGLONG

        referent = (
            ('Data', Array),
        )

    structure = (
        ('Count', dtypes.DWORD),
        ('Ptr', PArray),
    )


class StringArray(ndr.NDRSTRUCT):
    class PArray(ndr.NDRPOINTER):
        class Array(ndr.NDRUniConformantArray):
            item = dtypes.LPWSTR

        referent = (
            ('Data', Array),
        )

    structure = (
        ('Count', dtypes.DWORD),
        ('Ptr', PArray),
    )


class GuidArray(ndr.NDRSTRUCT):
    class PArray(ndr.NDRPOINTER):
        class Array(ndr.NDRUniConformantArray):
            item = dtypes.GUID

        referent = (
            ('Data', Array),
        )

    structure = (
        ('Count', dtypes.DWORD),
        ('Ptr', PArray),
    )


class EvtRpcVariantType(ndr.NDRENUM):
    align = 4
    structure = (
        ('Data', '<L'),
    )

    class enumItems(enum.Enum):
        Null = 0
        Boolean = 1
        UInt32 = 2
        UInt64 = 3
        String = 4
        Guid = 5
        BooleanArray = 6
        UInt32Array = 7
        UInt64Array = 8
        StringArray = 9
        GuidArray = 10


class EvtRpcVariantVal(ndr.NDRUNION):
    notAlign = True
    commonHdr = (
        ('tag', dtypes.ULONG),
    )
    union = {
        EvtRpcVariantType.Null: ('Null', dtypes.INT),
        EvtRpcVariantType.Boolean: ('Boolean', dtypes.BOOLEAN),
        EvtRpcVariantType.UInt32: ('UInt32', dtypes.ULONG),
        EvtRpcVariantType.UInt64: ('UInt64', dtypes.ULONGLONG),
        EvtRpcVariantType.String: ('String', dtypes.LPWSTR),
        EvtRpcVariantType.Guid: ('Guid', dtypes.PGUID),
        EvtRpcVariantType.BooleanArray: ('BooleanArray', BooleanArray),
        EvtRpcVariantType.UInt32Array: ('UInt32Array', UInt32Array),
        EvtRpcVariantType.UInt64Array: ('UInt64Array', UInt64Array),
        EvtRpcVariantType.StringArray: ('StringArray', StringArray),
        EvtRpcVariantType.GuidArray: ('GuidArray', GuidArray),
    }


class EvtRpcVariant(ndr.NDRSTRUCT):
    structure = (
        ('Type', EvtRpcVariantType),
        ('Flags', dtypes.DWORD),
        ('Val', EvtRpcVariantVal),
    )

    def getAlignment(self):
        align = 8
        childs_align = super(EvtRpcVariant, self).getAlignment()
        return max(align, childs_align)


class EvtRpcVariantList(ndr.NDRSTRUCT):
    class PArray(ndr.NDRPOINTER):
        class Array(ndr.NDRUniConformantArray):
            item = EvtRpcVariant

        referent = (
            ('Data', Array),
        )

    structure = (
        ('Count', dtypes.DWORD),
        ('Props', PArray),
    )


class ContextHandlePublisherMetadata(even6.CONTEXT_HANDLE_LOG_HANDLE):
    def getAlignment(self):
        return self.align


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


class EvtRpcMessageRender(ndr.NDRCALL):
    opnum = 9
    structure = (
        ('PubMetadataHandle', ContextHandlePublisherMetadata),
        ('SizeEventId', dtypes.DWORD),
        ('EventId', ndr.NDRUniConformantArray),
        ('MessageId', dtypes.DWORD),
        ('Values', EvtRpcVariantList),
        ('Flags', dtypes.DWORD),
        ('MaxSizeString', dtypes.DWORD),
    )


class EvtRpcMessageRenderResponse(ndr.NDRCALL):
    structure = (
        ('ActualSizeString', dtypes.DWORD),
        ('NeededSizeString', dtypes.DWORD),
        ('String,', even6.BYTE_ARRAY),
        ('Error', even6.RPC_INFO),
    )


class EvtRpcGetPublisherMetadata(ndr.NDRCALL):
    opnum = 24
    structure = (
        ('PublisherId', dtypes.LPWSTR),
        ('LogFilePath', dtypes.LPWSTR),
        ('Locale', LCID),
        ('Flags', dtypes.DWORD),
    )


class EvtRpcGetPublisherMetadataResponse(ndr.NDRCALL):
    structure = (
        ('PubMetadataProps', EvtRpcVariantList),
        ('PubMetadata', ContextHandlePublisherMetadata),
        ('Error', dtypes.ULONG),
    )


even6.OPNUMS[12] = (EvtRpcQuerySeekFixed, EvtRpcQuerySeekFixedResponse)
