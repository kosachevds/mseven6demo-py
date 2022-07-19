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
            item = ndr.NDRConformantVaryingString

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
        EvtRpcVarTypeNull = 0
        EvtRpcVarTypeBoolean = 1
        EvtRpcVarTypeUInt32 = 2
        EvtRpcVarTypeUInt64 = 3
        EvtRpcVarTypeString = 4
        EvtRpcVarTypeGuid = 5
        EvtRpcVarTypeBooleanArray = 6
        EvtRpcVarTypeUInt32Array = 7
        EvtRpcVarTypeUInt64Array = 8
        EvtRpcVarTypeStringArray = 9
        EvtRpcVarTypeGuidArray = 10


class PConformantVaryingString(ndr.NDRPOINTER):
    referent = (
        ('Data', ndr.NDRConformantVaryingString),
    )


class EvtRpcVariantVal(ndr.NDRUNION):
    notAlign = True
    commonHdr = (
        ('tag', dtypes.ULONG),
    )
    union = {
        EvtRpcVariantType.EvtRpcVarTypeNull: ('NullVal', dtypes.INT),
        EvtRpcVariantType.EvtRpcVarTypeBoolean: ('BooleanVal', dtypes.BOOLEAN),
        EvtRpcVariantType.EvtRpcVarTypeUInt32: ('UInt32Val', dtypes.ULONG),
        EvtRpcVariantType.EvtRpcVarTypeUInt64: ('UInt64Val', dtypes.ULONGLONG),
        EvtRpcVariantType.EvtRpcVarTypeString: ('StringVal', PConformantVaryingString),
        EvtRpcVariantType.EvtRpcVarTypeGuid: ('GuidVal', dtypes.PGUID),
        EvtRpcVariantType.EvtRpcVarTypeBooleanArray: ('BooleanArrayVal', BooleanArray),
        EvtRpcVariantType.EvtRpcVarTypeUInt32Array: ('UInt32ArrayVal', UInt32Array),
        EvtRpcVariantType.EvtRpcVarTypeUInt64Array: ('UInt64ArrayVal', UInt64Array),
        EvtRpcVariantType.EvtRpcVarTypeStringArray: ('StringArrayVal', StringArray),
        EvtRpcVariantType.EvtRpcVarTypeGuidArray: ('GuidArrayVal', GuidArray),
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


class LPWSTR_ARRAY(ndr.NDRUniVaryingArray):
    item = dtypes.LPWSTR


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
        ('PubMetadataHandle', even6.CONTEXT_HANDLE_LOG_HANDLE),
        ('SizeEventId', dtypes.DWORD),
        ('EventId', even6.BYTE_ARRAY),
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
        ('Other', ':'),
        # ("Raw", ":"),
        # ('PubMetadata', even6.CONTEXT_HANDLE_LOG_HANDLE),
        # ('Error', dtypes.ULONG),
    )


class EvtRpcGetPublisherListForChannel(ndr.NDRCALL):
    opnum = 23
    structure = (
        ('ChannelName', dtypes.WSTR),
        ('Flags', dtypes.DWORD),
    )


class EvtRpcGetPublisherListForChannelResponse(ndr.NDRCALL):
    structure = (
        ('NumPublisherIds', dtypes.DWORD),
        ('PublisherIds', LPWSTR_ARRAY),
        ('Error', dtypes.ULONG),
    )


even6.OPNUMS[12] = (EvtRpcQuerySeekFixed, EvtRpcQuerySeekFixedResponse)
even6.OPNUMS[23] = (EvtRpcGetPublisherListForChannel, EvtRpcGetPublisherListForChannelResponse)
