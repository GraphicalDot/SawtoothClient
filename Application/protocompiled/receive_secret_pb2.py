# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: receive_secret.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='receive_secret.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x14receive_secret.proto\"\x97\x01\n\rReceiveSecret\x12\x0e\n\x06\x61\x63tive\x18\x01 \x01(\x08\x12\x0c\n\x04role\x18\x02 \x01(\t\x12\x0b\n\x03idx\x18\x03 \x01(\r\x12\x12\n\ncreated_on\x18\x04 \x01(\t\x12\r\n\x05nonce\x18\x05 \x01(\r\x12\x12\n\nnonce_hash\x18\x06 \x01(\t\x12\x14\n\x0csigned_nonce\x18\x07 \x01(\t\x12\x0e\n\x06public\x18\x08 \x01(\tb\x06proto3')
)




_RECEIVESECRET = _descriptor.Descriptor(
  name='ReceiveSecret',
  full_name='ReceiveSecret',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='active', full_name='ReceiveSecret.active', index=0,
      number=1, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='role', full_name='ReceiveSecret.role', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='idx', full_name='ReceiveSecret.idx', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='created_on', full_name='ReceiveSecret.created_on', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='ReceiveSecret.nonce', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce_hash', full_name='ReceiveSecret.nonce_hash', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signed_nonce', full_name='ReceiveSecret.signed_nonce', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public', full_name='ReceiveSecret.public', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=25,
  serialized_end=176,
)

DESCRIPTOR.message_types_by_name['ReceiveSecret'] = _RECEIVESECRET
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ReceiveSecret = _reflection.GeneratedProtocolMessageType('ReceiveSecret', (_message.Message,), dict(
  DESCRIPTOR = _RECEIVESECRET,
  __module__ = 'receive_secret_pb2'
  # @@protoc_insertion_point(class_scope:ReceiveSecret)
  ))
_sym_db.RegisterMessage(ReceiveSecret)


# @@protoc_insertion_point(module_scope)
