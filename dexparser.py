from construct import *
from leb128 import LEB128sl, LEB128p1ul

# Requires construct >= 2.9!

header_item = Aligned(4, Struct(
        "magic" / Union(0,
            "raw" / Bytes(8),
            "version" / Struct(Const(b"dex\n"),
            "dexversion" / Bytes(3),
            Const(b"\x00"))),
        "checksum" / Int32ul,
        "signature" / Bytes(20),
        "file_size" / Int32ul,
        "header_size" / Const(value=0x70, subcon=Int32ul),
        "endian_tag" / Const(value=0x12345678, subcon=Int32ul),
        "link_size" / Int32ul,
        "link_off" / Int32ul,
        "map_off" / Int32ul,
        "string_ids_size" / Int32ul,
        "string_ids_off" / Int32ul,
        "type_ids_size" / Int32ul,
        "type_ids_off" / Int32ul,
        "proto_ids_size" / Int32ul,
        "proto_ids_off" / Int32ul,
        "field_ids_size" / Int32ul,
        "field_ids_off" / Int32ul,
        "method_ids_size" / Int32ul,
        "method_ids_off" / Int32ul,
        "class_defs_size" / Int32ul,
        "class_defs_off" / Int32ul,
        "data_size" / Int32ul,
        "data_off" / Int32ul,
))

call_site_id_item = Aligned(4, Struct(
        "call_site_off" / Int32ul,
        ))

method_handle_item = Aligned(4, Struct(
        "method_handle_type" / Aligned(4, Int16ul),
        "field_or_method_id" / Aligned(4, Int16ul),
        ))

type_item = Struct(
        "type_idx" / Int16ul,
        )

type_list = Aligned(4, Struct(
        "size" / Int32ul,
        "list" / Array(this.size, type_item),
        ))

annotation_set_ref_item = Struct(
        "annotations_off" / Int32ul,
        )

annotation_set_ref_list = Aligned(4, Struct(
        "size" / Int32ul,
        "list" / Array(this.size, annotation_set_ref_item),
        ))

annotation_off_item = Struct(
        "annotation_off" / Int32ul,
        )

annotation_set_item = Aligned(4, Struct(
        "size" / Int32ul,
        "entries" / Array(this.size, annotation_off_item),
        ))

encoded_field = Struct(
        "field_idx_diff" / VarInt,
        "access_flags" / VarInt,
        )

encoded_method = Struct(
        "method_idx_diff" / VarInt,
        "access_flags" / VarInt,
        "code_off" / VarInt,
        )

class_data_item = Struct(
        "static_fields_size" / VarInt,
        "instance_fields_size" / VarInt,
        "direct_methods_size" / VarInt,
        "virtual_methods_size" / VarInt,
        "static_fields" / Array(this.static_fields_size, encoded_field),
        "instance_fields" / Array(this.instance_fields_size, encoded_field),
        "direct_methods" / Array(this.direct_methods_size, encoded_method),
        "virtual_methods" / Array(this.virtual_methods_size, encoded_method),
        )

try_item = Struct(
        "start_addr" / Int32ul,
        "insn_count" / Int16ul,
        "handler_off" / Int16ul,
        )

encoded_type_addr_pair = Struct(
        "type_idx" / VarInt,
        "addr" / VarInt,
        )

encoded_catch_handler = Struct(
        "size" / LEB128sl,
        "handlers" / Array(abs_(this.size), encoded_type_addr_pair),
        "catch_all_addr" / If(this.size <= 0, VarInt),
        )

encoded_catch_handler_list = Struct(
        "size" / VarInt,
        "list" / Array(this.size, encoded_catch_handler),
        )

code_item = Aligned(4, Struct(
        "registers_size" / Int16ul,
        "ins_size" / Int16ul,
        "outs_size" / Int16ul,
        "tries_size" / Int16ul,
        "debug_info_off" / Int32ul,
        "insns_size" / Int32ul,
        "insns" / Bytes(this.insns_size * 2),
        "padding" / If(this.tries_size > 0 and (this.insns_size % 2 == 1),
            Const(b"\x00\x00"),
        ),
        "tries" / If(this.tries_size > 0, Array(this.tries_size, try_item)),
        "handlers" / If(this.tries_size > 0, encoded_catch_handler_list),
        ))

string_data_item = Struct(
        "utf16_size" / VarInt,
        # FIXME: Workaround for missing MUTF-8 Parser
        "data" / RepeatUntil(lambda obj,lst,ctx: obj == 0, Byte)
        )

debug_info_item = Struct(
        "line_start" / VarInt,
        "parameters_size" / VarInt,
        "parameter_names" / Array(this.parameters_size, LEB128p1ul),
        "bytecode" / RepeatUntil(lambda obj,lst,ctx: obj == 0, Byte)
        )

encoded_array = Struct(
        "size" / VarInt,
        "values" / Array(this.size, LazyBound(lambda: encoded_value)),
        )
annotation_element = Struct(
        "name_idx" / VarInt,
        "value" / LazyBound(lambda: encoded_value),
        )


encoded_array_item = Struct(
        "value" / encoded_array,
        )

encoded_annotation = Struct(
        "type_idx" / VarInt,
        "size" / VarInt,
        "elements" / Array(this.size, annotation_element),
        )

encoded_value = Struct(
        "xxx" / Bitwise(Struct(
            "value_arg" / BitsInteger(3),
            "value_type" / Enum(BitsInteger(5),
                VALUE_BYTE = 0x00,
                VALUE_SHORT = 0x02,
                VALUE_CHAR = 0x03,
                VALUE_INT = 0x04,
                VALUE_LONG = 0x06,
                VALUE_FLOAT = 0x10,
                VALUE_DOUBLE = 0x11,
                VALUE_METHOD_TYPE = 0x15,
                VALUE_METHOD_HANDLE = 0x16,
                VALUE_STRING = 0x17,
                VALUE_TYPE = 0x18,
                VALUE_FIELD = 0x19,
                VALUE_METHOD = 0x1a,
                VALUE_ENUM = 0x1b,
                VALUE_ARRAY = 0x1c,
                VALUE_ANNOTATION = 0x1d,
                VALUE_NULL = 0x1e,
                VALUE_BOOLEAN = 0x1f,
                ),
            )),
        "value" / Switch(this.xxx.value_type, {
                "VALUE_BYTE" : Int8ul,
                "VALUE_SHORT" : Bytes(this.xxx.value_arg + 1),
                "VALUE_CHAR" : Bytes(this.xxx.value_arg + 1),
                "VALUE_INT" : Bytes(this.xxx.value_arg + 1),
                "VALUE_LONG" : Bytes(this.xxx.value_arg + 1),
                "VALUE_FLOAT" : Bytes(this.xxx.value_arg + 1),
                "VALUE_DOUBLE" : Bytes(this.xxx.value_arg + 1),
                "VALUE_METHOD_TYPE" : Bytes(this.xxx.value_arg + 1),
                "VALUE_METHOD_HANDLE" : Bytes(this.xxx.value_arg + 1),
                "VALUE_STRING" : Bytes(this.xxx.value_arg + 1),
                "VALUE_TYPE" : Bytes(this.xxx.value_arg + 1),
                "VALUE_FIELD" : Bytes(this.xxx.value_arg + 1),
                "VALUE_METHOD" : Bytes(this.xxx.value_arg + 1),
                "VALUE_ENUM" : Bytes(this.xxx.value_arg + 1),
                "VALUE_ARRAY" : encoded_array,
                "VALUE_ANNOTATION" : encoded_annotation,
                "VALUE_NULL" : Pass,
                "VALUE_BOOLEAN" : Pass,
            }, default=Pass),
        )



annotation_item = Struct(
        "visibility" / Enum(Int8ul,
            VISIBILITY_BUILD = 0x00,
            VISIBILITY_RUNTIME = 0x01,
            VISIBILITY_SYSTEM = 0x02,
            ),
        "annotation" / encoded_annotation,
        )

field_annotation = Struct(
        "field_idx" / Int32ul,
        "annotations_off" / Int32ul,
        )

method_annotation = Struct(
        "method_idx" / Int32ul,
        "annotations_off" / Int32ul,
        )

parameter_annotation = Struct(
        "method_idx" / Int32ul,
        "annotations_off" / Int32ul,
        )


annotations_directory_item = Aligned(4, Struct(
        "class_annotations_off" / Int32ul,
        "fields_size" / Int32ul,
        "annotated_methods_size" / Int32ul,
        "annotated_parameters_size" / Int32ul,
        "field_annotations" / Array(this.fields_size, field_annotation),
        "method_annotations" / Array(this.annotated_methods_size, method_annotation),
        "parameter_annotations" / Array(this.annotated_parameters_size, parameter_annotation),
        ))






string_id_item = Aligned(4, Struct(
        "string_data_off" / Int32ul,
))

type_id_item = Aligned(4, Struct(
        "descriptor_idx" / Int32ul,
))

proto_id_item = Aligned(4, Struct(
        "shorty_idx" / Int32ul,
        "return_type_idx" / Int32ul,
        "parameters_off" / Int32ul
))

field_id_item = Aligned(4, Struct(
        "class_idx" / Int16ul,
        "type_idx" / Int16ul,
        "name_idx" / Int32ul,
))

method_id_item = Aligned(4, Struct(
        "class_idx" / Int16ul,
        "proto_idx" / Int16ul,
        "name_idx" / Int32ul,
))

class_def_item = Aligned(4, Struct(
        "class_idx" / Int32ul,
        "access_flags" / FlagsEnum(Int32ul,
            ACC_PUBLIC = 0x1,
            ACC_PRIVATE = 0x2,
            ACC_PROTECTED = 0x4,
            ACC_STATIC = 0x8,
            ACC_FINAL = 0x10,
            ACC_INTERFACE = 0x200,
            ACC_ABSTRACT = 0x400,
            ACC_SYNTHETIC = 0x1000,
            ACC_ANNOTATION = 0x2000,
            ACC_ENUM = 0x4000
            ),
        "superclass_idx" / Int32ul,
        "interfaces_off" / Int32ul,
        "source_file_idx" / Int32ul,
        "annotations_off" / Int32ul,
        "class_data_off" / Int32ul,
        "static_values_off" / Int32ul,
))

map_item = Struct(
        "type" / Enum(Int16ul,
            TYPE_HEADER_ITEM = 0x0000,
            TYPE_STRING_ID_ITEM = 0x0001,
            TYPE_TYPE_ID_ITEM = 0x0002,
            TYPE_PROTO_ID_ITEM = 0x0003,
            TYPE_FIELD_ID_ITEM = 0x0004,
            TYPE_METHOD_ID_ITEM = 0x0005,
            TYPE_CLASS_DEF_ITEM = 0x0006,
            TYPE_CALL_SITE_ID_ITEM = 0x0007,
            TYPE_METHOD_HANDLE_ITEM = 0x0008,
            TYPE_MAP_LIST = 0x1000,
            TYPE_TYPE_LIST = 0x1001,
            TYPE_ANNOTATION_SET_REF_LIST = 0x1002,
            TYPE_ANNOTATION_SET_ITEM = 0x1003,
            TYPE_CLASS_DATA_ITEM = 0x2000,
            TYPE_CODE_ITEM = 0x2001,
            TYPE_STRING_DATA_ITEM = 0x2002,
            TYPE_DEBUG_INFO_ITEM = 0x2003,
            TYPE_ANNOTATION_ITEM = 0x2004,
            TYPE_ENCODED_ARRAY_ITEM = 0x2005,
            TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006,
            ),
        "unused" / Int16ul,
        "size" / Int32ul,
        "offset" / Int32ul,

        "item" / Pointer(this.offset, Struct(
            "items" / Array(this._.size,
                Switch(this._.type, {
                    # we already got that...
                    "TYPE_HEADER_ITEM" : header_item,
                    "TYPE_STRING_ID_ITEM" : string_id_item,
                    "TYPE_TYPE_ID_ITEM" : type_id_item,
                    "TYPE_PROTO_ID_ITEM" : proto_id_item,
                    "TYPE_FIELD_ID_ITEM" : field_id_item,
                    "TYPE_METHOD_ID_ITEM" : method_id_item,
                    "TYPE_CLASS_DEF_ITEM" : class_def_item,
                    "TYPE_CALL_SITE_ID_ITEM" : call_site_id_item,
                    "TYPE_METHOD_HANDLE_ITEM" : method_handle_item,
                    # itself...
                    # "TYPE_MAP_LIST" : map_list,
                    "TYPE_TYPE_LIST" : type_list,
                    "TYPE_ANNOTATION_SET_REF_LIST" : annotation_set_ref_list,
                    "TYPE_ANNOTATION_SET_ITEM" : annotation_set_item,
                    "TYPE_CLASS_DATA_ITEM" : class_data_item,
                    "TYPE_CODE_ITEM" : code_item,
                    "TYPE_STRING_DATA_ITEM" : string_data_item,
                    "TYPE_DEBUG_INFO_ITEM" : debug_info_item,
                    "TYPE_ANNOTATION_ITEM" : annotation_item,
                    "TYPE_ENCODED_ARRAY_ITEM" : encoded_array_item,
                    "TYPE_ANNOTATIONS_DIRECTORY_ITEM" : annotations_directory_item,
                    }, default=Pass)),
            )),
)

map_list = Aligned(4, Struct(
        "size" / Int32ul,
        "list" / Array(this.size, map_item),
))

dexfile = Struct(
        "header_item" / header_item,
        Seek(this.header_item.map_off),
        "map_list" / map_list,

        # TODO not reading link...

)

if __name__ == "__main__":
    with open("classes.dex", "rb") as fp:
        print(dexfile.parse(fp.read()))


