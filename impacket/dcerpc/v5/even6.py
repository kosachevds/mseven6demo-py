# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
# Copyright (c) 2017 @MrAnde7son
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Initial [MS-EVEN6] Interface implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/SecureAuthCorp/impacket/tree/master/tests/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file.
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too.
#
# Author:
#   Itamar (@MrAnde7son)
#
import struct
from impacket import system_errors, LOG
from impacket.dcerpc.v5.dtypes import WSTR, DWORD, LPWSTR, ULONG, LARGE_INTEGER, WORD, BYTE
from impacket.dcerpc.v5.ndr import NDR, NDRCALL, NDRCONSTRUCTEDTYPE, NDRPOINTER, NDRUniConformantArray, NDRUniConformantVaryingArray, NDRUniVaryingArray, NDRSTRUCT
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_EVEN6 = uuidtup_to_bin(('F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C', '1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'EVEN6 SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EVEN6 SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################

# Evt Path Flags
EvtQueryChannelName = 0x00000001
EvtQueryFilePath = 0x00000002
EvtReadOldestToNewest = 0x00000100
EvtReadNewestToOldest = 0x00000200

################################################################################
# STRUCTURES
################################################################################

class CONTEXT_HANDLE_LOG_HANDLE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s=""'),
    )

class PCONTEXT_HANDLE_LOG_HANDLE(NDRPOINTER):
    referent = (
        ('Data', CONTEXT_HANDLE_LOG_HANDLE),
    )

class CONTEXT_HANDLE_LOG_QUERY(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s=""'),
    )

class PCONTEXT_HANDLE_LOG_QUERY(NDRPOINTER):
    referent = (
        ('Data', CONTEXT_HANDLE_LOG_QUERY),
    )

class LPPCONTEXT_HANDLE_LOG_QUERY(NDRPOINTER):
    referent = (
        ('Data', PCONTEXT_HANDLE_LOG_QUERY),
    )

class CONTEXT_HANDLE_OPERATION_CONTROL(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s=""'),
    )

class PCONTEXT_HANDLE_OPERATION_CONTROL(NDRPOINTER):
    referent = (
        ('Data', CONTEXT_HANDLE_OPERATION_CONTROL),
    )

# 2.2.11 EvtRpcQueryChannelInfo
class EvtRpcQueryChannelInfo(NDRSTRUCT):
    structure = (
        ('Name', LPWSTR),
        ('Status', DWORD),
    )

class EvtRpcQueryChannelInfoArray(NDRUniVaryingArray):
    item = EvtRpcQueryChannelInfo

class LPEvtRpcQueryChannelInfoArray(NDRPOINTER):
    referent = (
        ('Data', EvtRpcQueryChannelInfoArray)
    )

class RPC_INFO(NDRSTRUCT):
    structure = (
        ('Error', DWORD),
        ('SubError', DWORD),
        ('SubErrorParam', DWORD),
    )

class PRPC_INFO(NDRPOINTER):
    referent = (
        ('Data', RPC_INFO)
    )

class WSTR_ARRAY(NDRUniVaryingArray):
    item = WSTR

class DWORD_ARRAY(NDRUniVaryingArray):
    item = DWORD

class LPDWORD_ARRAY(NDRPOINTER):
    referent = (
        ('Data', DWORD_ARRAY)
    )

class BYTE_ARRAY(NDRUniVaryingArray):
    item = 'c'

class CBYTE_ARRAY(NDRUniVaryingArray):
    item = BYTE

class CDWORD_ARRAY(NDRUniConformantArray):
    item = DWORD

class LPBYTE_ARRAY(NDRPOINTER):
    referent = (
        ('Data', CBYTE_ARRAY)
    )

class ULONG_ARRAY(NDRUniVaryingArray):
    item = ULONG

# 2.3.1 EVENT_DESCRIPTOR
class EVENT_DESCRIPTOR(NDRSTRUCT):
    structure = (
        ('Id', WORD),
        ('Version', BYTE),
        ('Channel', BYTE),
        ('LevelSeverity', BYTE),
        ('Opcode', BYTE),
        ('Task', WORD),
        ('Keyword', ULONG),
    )

class BOOKMARK(NDRSTRUCT):
    structure = (
        ('BookmarkSize', DWORD),
        ('HeaderSize', '<L=0x18'),
        ('ChannelSize', DWORD),
        ('CurrentChannel', DWORD),
        ('ReadDirection', DWORD),
        ('RecordIdsOffset', DWORD),
        ('LogRecordNumbers', ULONG_ARRAY),
    )


#2.2.17 RESULT_SET
class RESULT_SET(NDRSTRUCT):
    structure = (
        ('TotalSize', DWORD),
        ('HeaderSize', DWORD),
        ('EventOffset', DWORD),
        ('BookmarkOffset', DWORD),
        ('BinXmlSize', DWORD),
        ('EventData', BYTE_ARRAY),
        #('NumberOfSubqueryIDs', '<L=0'),
        #('SubqueryIDs', BYTE_ARRAY),
        #('BookMarkData', BOOKMARK),
    )

################################################################################
# RPC CALLS
################################################################################

class EvtRpcRegisterLogQuery(NDRCALL):
    opnum = 5
    structure = (
        ('Path', LPWSTR),
        ('Query', WSTR),
        ('Flags', DWORD),
    )

class EvtRpcRegisterLogQueryResponse(NDRCALL):
    structure = (
        ('Handle', CONTEXT_HANDLE_LOG_QUERY),
        ('OpControl', CONTEXT_HANDLE_OPERATION_CONTROL),
        ('QueryChannelInfoSize', DWORD),
        ('QueryChannelInfo', EvtRpcQueryChannelInfoArray),
        ('Error', RPC_INFO),
        )

class EvtRpcQueryNext(NDRCALL):
    opnum = 11
    structure = (
        ('LogQuery', CONTEXT_HANDLE_LOG_QUERY),
        ('NumRequestedRecords', DWORD),
        ('TimeOutEnd', DWORD),
        ('Flags', DWORD),
    )


class QueryNextResponseDwordArray(NDRUniVaryingArray):
    item = DWORD

    def fromString(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.structure:
            try:
                offset += self.calculatePad(fieldTypeOrClass, offset)
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise
        return offset - offset0

    def unpack(self, fieldName, fieldTypeOrClass, data, offset=0):
        # array specifier
        two = fieldTypeOrClass.split('*')
        if len(two) != 2:
            return NDRCONSTRUCTEDTYPE.unpack(self, fieldName, fieldTypeOrClass, data, offset)

        # The item type is determined by self.item
        dataClassOrCode = self.item
        self.fields['_tmpItem'] = dataClassOrCode(isNDR64=self._isNDR64)
        numItems = self[two[1]]
        nsofar = 0
        answer = []
        soFarItems = 0
        offset0 = offset
        while numItems and soFarItems < len(data) - offset:
            # TODO unpack all items at once
            itemn = dataClassOrCode(isNDR64=self._isNDR64)
            size = itemn.fromString(data, offset+soFarItems)
            answer.append(itemn)
            nsofar += size
            numItems -= 1
            soFarItems = nsofar
        del(self.fields['_tmpItem'])
        self.fields[fieldName] = answer
        return soFarItems + offset - offset0

class QueryNextResponseByteArray(NDRUniVaryingArray):
    item = 'c'

    def fromString(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.structure:
            try:
                offset += self.calculatePad(fieldTypeOrClass, offset)
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise
        return offset - offset0

    # @jit
    def unpack(self, fieldName, fieldTypeOrClass, data, offset=0):
        # array specifier
        two = fieldTypeOrClass.split('*')
        if len(two) != 2:
            return NDRCONSTRUCTEDTYPE.unpack(self, fieldName, fieldTypeOrClass, data, offset)

        offset0 = offset
        numItems = self[two[1]]
        # The item type is determined by self.item
        item = self.item
        dataClassOrCode = None
        self.fields['_tmpItem'] = item

        soFarItems = 0
        answer = bytes(data[offset:offset + numItems])
        del(self.fields['_tmpItem'])
        self.fields[fieldName] = answer
        return soFarItems + offset - offset0

class EvtRpcQueryNextResponse(NDRCALL):
    structure = (
        ('NumActualRecords', DWORD),
        ('EventDataIndices', QueryNextResponseDwordArray),
        ('EventDataSizes', QueryNextResponseDwordArray),
        ('ResultBufferSize', DWORD),
        ('ResultBuffer', QueryNextResponseByteArray),
        ('ErrorCode', ULONG),
    )

    def __init__(self, data=None, isNDR64=False):
        self.__constructed_fields = set([
            'EventDataIndices', 'EventDataSizes', 'ResultBuffer'])
        super().__init__(data, isNDR64)

    def fromString(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.structure:
            try:
                size = self.fields[fieldName].fromString(data, offset)
                if fieldName in self.__constructed_fields:
                    size += self.fields[fieldName].fromStringReferents(data, offset+size)
                    size += self.fields[fieldName].fromStringReferent(data, offset+size)
                offset += size
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise
        return offset - offset0


class EvtRpcQuerySeek(NDRCALL):
    opnum = 12
    structure = (
        ('LogQuery', CONTEXT_HANDLE_LOG_QUERY),
        ('Pos', LARGE_INTEGER),
        ('BookmarkXML', LPWSTR),
        ('Flags', DWORD),
    )

class EvtRpcQuerySeekResponse(NDRCALL):
    structure = (
        ('Error', RPC_INFO),
    )

class EvtRpcClose(NDRCALL):
    opnum = 13
    structure = (
        ("Handle", CONTEXT_HANDLE_LOG_HANDLE),
    )

class EvtRpcCloseResponse(NDRCALL):
    structure = (
        ("Handle", PCONTEXT_HANDLE_LOG_HANDLE),
        ('ErrorCode', ULONG),
    )

class EvtRpcOpenLogHandle(NDRCALL):
    opnum = 17
    structure = (
        ('Channel', WSTR),
        ('Flags', DWORD),
    )

class EvtRpcOpenLogHandleResponse(NDRCALL):
    structure = (
        ('Handle', PCONTEXT_HANDLE_LOG_HANDLE),
        ('Error', RPC_INFO),
    )

class EvtRpcGetChannelList(NDRCALL):
    opnum = 19
    structure = (
        ('Flags', DWORD),
    )

class EvtRpcGetChannelListResponse(NDRCALL):
    structure = (
        ('NumChannelPaths', DWORD),
        ('ChannelPaths', WSTR_ARRAY),
        ('ErrorCode', ULONG),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################

OPNUMS = {
    5   : (EvtRpcRegisterLogQuery, EvtRpcRegisterLogQueryResponse),
    11  : (EvtRpcQueryNext,  EvtRpcQueryNextResponse),
    12  : (EvtRpcQuerySeek, EvtRpcQuerySeekResponse),
    13  : (EvtRpcClose, EvtRpcCloseResponse),
    17  : (EvtRpcOpenLogHandle, EvtRpcOpenLogHandle),
    19  : (EvtRpcGetChannelList, EvtRpcGetChannelListResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################

def hEvtRpcRegisterLogQuery(dce, path, flags, query='*\x00'):
    request = EvtRpcRegisterLogQuery()

    request['Path'] = path
    request['Query'] = query
    request['Flags'] = flags
    resp = dce.request(request)
    return resp

def hEvtRpcQueryNext(dce, handle, numRequestedRecords, timeOutEnd=1000):
    request = EvtRpcQueryNext()

    request['LogQuery'] = handle
    request['NumRequestedRecords'] = numRequestedRecords
    request['TimeOutEnd'] = timeOutEnd
    request['Flags'] = 0
    status = system_errors.ERROR_MORE_DATA
    resp = dce.request(request)
    while status == system_errors.ERROR_MORE_DATA:
        try:
            resp = dce.request(request)
        except DCERPCException as e:
            if str(e).find('ERROR_NO_MORE_ITEMS') < 0:
                raise
            elif str(e).find('ERROR_TIMEOUT') < 0:
                raise
            resp = e.get_packet()
        return resp

def hEvtRpcClose(dce, handle):
    request = EvtRpcClose()
    request['Handle'] = handle
    resp = dce.request(request)
    return resp

def hEvtRpcOpenLogHandle(dce, channel, flags):
    request = EvtRpcOpenLogHandle()

    request['Channel'] = channel
    request['Flags'] = flags
    return dce.request(request)

def hEvtRpcGetChannelList(dce):
    request = EvtRpcGetChannelList()

    request['Flags'] = 0
    resp = dce.request(request)
    return resp
