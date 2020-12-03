// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: scd.proto

package com.webank.wedpr.scd.proto;

/**
 *
 *
 * <pre>
 * Predicate rule.
 * </pre>
 *
 * Protobuf type {@code com.webank.wedpr.scd.proto.Predicate}
 */
public final class Predicate extends com.google.protobuf.GeneratedMessageV3
    implements
    // @@protoc_insertion_point(message_implements:com.webank.wedpr.scd.proto.Predicate)
    PredicateOrBuilder {
  private static final long serialVersionUID = 0L;
  // Use Predicate.newBuilder() to construct.
  private Predicate(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }

  private Predicate() {
    attributeName_ = "";
    predicateType_ = "";
  }

  @Override
  @SuppressWarnings({"unused"})
  protected Object newInstance(UnusedPrivateParameter unused) {
    return new Predicate();
  }

  @Override
  public final com.google.protobuf.UnknownFieldSet getUnknownFields() {
    return this.unknownFields;
  }

  private Predicate(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new NullPointerException();
    }
    com.google.protobuf.UnknownFieldSet.Builder unknownFields =
        com.google.protobuf.UnknownFieldSet.newBuilder();
    try {
      boolean done = false;
      while (!done) {
        int tag = input.readTag();
        switch (tag) {
          case 0:
            done = true;
            break;
          case 10:
            {
              String s = input.readStringRequireUtf8();

              attributeName_ = s;
              break;
            }
          case 18:
            {
              String s = input.readStringRequireUtf8();

              predicateType_ = s;
              break;
            }
          case 24:
            {
              predicateValue_ = input.readUInt64();
              break;
            }
          default:
            {
              if (!parseUnknownField(input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
        }
      }
    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
      throw e.setUnfinishedMessage(this);
    } catch (java.io.IOException e) {
      throw new com.google.protobuf.InvalidProtocolBufferException(e).setUnfinishedMessage(this);
    } finally {
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }

  public static final com.google.protobuf.Descriptors.Descriptor getDescriptor() {
    return com.webank.wedpr.scd.proto.Scd
        .internal_static_com_webank_wedpr_scd_proto_Predicate_descriptor;
  }

  @Override
  protected FieldAccessorTable internalGetFieldAccessorTable() {
    return com.webank.wedpr.scd.proto.Scd
        .internal_static_com_webank_wedpr_scd_proto_Predicate_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.webank.wedpr.scd.proto.Predicate.class,
            com.webank.wedpr.scd.proto.Predicate.Builder.class);
  }

  public static final int ATTRIBUTE_NAME_FIELD_NUMBER = 1;
  private volatile Object attributeName_;
  /** <code>string attribute_name = 1;</code> */
  public String getAttributeName() {
    Object ref = attributeName_;
    if (ref instanceof String) {
      return (String) ref;
    } else {
      com.google.protobuf.ByteString bs = (com.google.protobuf.ByteString) ref;
      String s = bs.toStringUtf8();
      attributeName_ = s;
      return s;
    }
  }
  /** <code>string attribute_name = 1;</code> */
  public com.google.protobuf.ByteString getAttributeNameBytes() {
    Object ref = attributeName_;
    if (ref instanceof String) {
      com.google.protobuf.ByteString b = com.google.protobuf.ByteString.copyFromUtf8((String) ref);
      attributeName_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int PREDICATE_TYPE_FIELD_NUMBER = 2;
  private volatile Object predicateType_;
  /** <code>string predicate_type = 2;</code> */
  public String getPredicateType() {
    Object ref = predicateType_;
    if (ref instanceof String) {
      return (String) ref;
    } else {
      com.google.protobuf.ByteString bs = (com.google.protobuf.ByteString) ref;
      String s = bs.toStringUtf8();
      predicateType_ = s;
      return s;
    }
  }
  /** <code>string predicate_type = 2;</code> */
  public com.google.protobuf.ByteString getPredicateTypeBytes() {
    Object ref = predicateType_;
    if (ref instanceof String) {
      com.google.protobuf.ByteString b = com.google.protobuf.ByteString.copyFromUtf8((String) ref);
      predicateType_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int PREDICATE_VALUE_FIELD_NUMBER = 3;
  private long predicateValue_;
  /** <code>uint64 predicate_value = 3;</code> */
  public long getPredicateValue() {
    return predicateValue_;
  }

  private byte memoizedIsInitialized = -1;

  @Override
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  @Override
  public void writeTo(com.google.protobuf.CodedOutputStream output) throws java.io.IOException {
    if (!getAttributeNameBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, attributeName_);
    }
    if (!getPredicateTypeBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, predicateType_);
    }
    if (predicateValue_ != 0L) {
      output.writeUInt64(3, predicateValue_);
    }
    unknownFields.writeTo(output);
  }

  @Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!getAttributeNameBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, attributeName_);
    }
    if (!getPredicateTypeBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, predicateType_);
    }
    if (predicateValue_ != 0L) {
      size += com.google.protobuf.CodedOutputStream.computeUInt64Size(3, predicateValue_);
    }
    size += unknownFields.getSerializedSize();
    memoizedSize = size;
    return size;
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof com.webank.wedpr.scd.proto.Predicate)) {
      return super.equals(obj);
    }
    com.webank.wedpr.scd.proto.Predicate other = (com.webank.wedpr.scd.proto.Predicate) obj;

    if (!getAttributeName().equals(other.getAttributeName())) return false;
    if (!getPredicateType().equals(other.getPredicateType())) return false;
    if (getPredicateValue() != other.getPredicateValue()) return false;
    if (!unknownFields.equals(other.unknownFields)) return false;
    return true;
  }

  @Override
  public int hashCode() {
    if (memoizedHashCode != 0) {
      return memoizedHashCode;
    }
    int hash = 41;
    hash = (19 * hash) + getDescriptor().hashCode();
    hash = (37 * hash) + ATTRIBUTE_NAME_FIELD_NUMBER;
    hash = (53 * hash) + getAttributeName().hashCode();
    hash = (37 * hash) + PREDICATE_TYPE_FIELD_NUMBER;
    hash = (53 * hash) + getPredicateType().hashCode();
    hash = (37 * hash) + PREDICATE_VALUE_FIELD_NUMBER;
    hash = (53 * hash) + com.google.protobuf.Internal.hashLong(getPredicateValue());
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(
      java.nio.ByteBuffer data, com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(
      byte[] data, com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3.parseWithIOException(PARSER, input);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(
      java.io.InputStream input, com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3.parseWithIOException(
        PARSER, input, extensionRegistry);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3.parseDelimitedWithIOException(PARSER, input);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseDelimitedFrom(
      java.io.InputStream input, com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3.parseDelimitedWithIOException(
        PARSER, input, extensionRegistry);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(
      com.google.protobuf.CodedInputStream input) throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3.parseWithIOException(PARSER, input);
  }

  public static com.webank.wedpr.scd.proto.Predicate parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3.parseWithIOException(
        PARSER, input, extensionRegistry);
  }

  @Override
  public Builder newBuilderForType() {
    return newBuilder();
  }

  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }

  public static Builder newBuilder(com.webank.wedpr.scd.proto.Predicate prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }

  @Override
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE ? new Builder() : new Builder().mergeFrom(this);
  }

  @Override
  protected Builder newBuilderForType(BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   *
   *
   * <pre>
   * Predicate rule.
   * </pre>
   *
   * Protobuf type {@code com.webank.wedpr.scd.proto.Predicate}
   */
  public static final class Builder extends com.google.protobuf.GeneratedMessageV3.Builder<Builder>
      implements
      // @@protoc_insertion_point(builder_implements:com.webank.wedpr.scd.proto.Predicate)
      com.webank.wedpr.scd.proto.PredicateOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor getDescriptor() {
      return com.webank.wedpr.scd.proto.Scd
          .internal_static_com_webank_wedpr_scd_proto_Predicate_descriptor;
    }

    @Override
    protected FieldAccessorTable internalGetFieldAccessorTable() {
      return com.webank.wedpr.scd.proto.Scd
          .internal_static_com_webank_wedpr_scd_proto_Predicate_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.webank.wedpr.scd.proto.Predicate.class,
              com.webank.wedpr.scd.proto.Predicate.Builder.class);
    }

    // Construct using com.webank.wedpr.scd.proto.Predicate.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }

    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders) {}
    }

    @Override
    public Builder clear() {
      super.clear();
      attributeName_ = "";

      predicateType_ = "";

      predicateValue_ = 0L;

      return this;
    }

    @Override
    public com.google.protobuf.Descriptors.Descriptor getDescriptorForType() {
      return com.webank.wedpr.scd.proto.Scd
          .internal_static_com_webank_wedpr_scd_proto_Predicate_descriptor;
    }

    @Override
    public com.webank.wedpr.scd.proto.Predicate getDefaultInstanceForType() {
      return com.webank.wedpr.scd.proto.Predicate.getDefaultInstance();
    }

    @Override
    public com.webank.wedpr.scd.proto.Predicate build() {
      com.webank.wedpr.scd.proto.Predicate result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @Override
    public com.webank.wedpr.scd.proto.Predicate buildPartial() {
      com.webank.wedpr.scd.proto.Predicate result = new com.webank.wedpr.scd.proto.Predicate(this);
      result.attributeName_ = attributeName_;
      result.predicateType_ = predicateType_;
      result.predicateValue_ = predicateValue_;
      onBuilt();
      return result;
    }

    @Override
    public Builder clone() {
      return super.clone();
    }

    @Override
    public Builder setField(com.google.protobuf.Descriptors.FieldDescriptor field, Object value) {
      return super.setField(field, value);
    }

    @Override
    public Builder clearField(com.google.protobuf.Descriptors.FieldDescriptor field) {
      return super.clearField(field);
    }

    @Override
    public Builder clearOneof(com.google.protobuf.Descriptors.OneofDescriptor oneof) {
      return super.clearOneof(oneof);
    }

    @Override
    public Builder setRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field, int index, Object value) {
      return super.setRepeatedField(field, index, value);
    }

    @Override
    public Builder addRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field, Object value) {
      return super.addRepeatedField(field, value);
    }

    @Override
    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof com.webank.wedpr.scd.proto.Predicate) {
        return mergeFrom((com.webank.wedpr.scd.proto.Predicate) other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.webank.wedpr.scd.proto.Predicate other) {
      if (other == com.webank.wedpr.scd.proto.Predicate.getDefaultInstance()) return this;
      if (!other.getAttributeName().isEmpty()) {
        attributeName_ = other.attributeName_;
        onChanged();
      }
      if (!other.getPredicateType().isEmpty()) {
        predicateType_ = other.predicateType_;
        onChanged();
      }
      if (other.getPredicateValue() != 0L) {
        setPredicateValue(other.getPredicateValue());
      }
      this.mergeUnknownFields(other.unknownFields);
      onChanged();
      return this;
    }

    @Override
    public final boolean isInitialized() {
      return true;
    }

    @Override
    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      com.webank.wedpr.scd.proto.Predicate parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (com.webank.wedpr.scd.proto.Predicate) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private Object attributeName_ = "";
    /** <code>string attribute_name = 1;</code> */
    public String getAttributeName() {
      Object ref = attributeName_;
      if (!(ref instanceof String)) {
        com.google.protobuf.ByteString bs = (com.google.protobuf.ByteString) ref;
        String s = bs.toStringUtf8();
        attributeName_ = s;
        return s;
      } else {
        return (String) ref;
      }
    }
    /** <code>string attribute_name = 1;</code> */
    public com.google.protobuf.ByteString getAttributeNameBytes() {
      Object ref = attributeName_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8((String) ref);
        attributeName_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /** <code>string attribute_name = 1;</code> */
    public Builder setAttributeName(String value) {
      if (value == null) {
        throw new NullPointerException();
      }

      attributeName_ = value;
      onChanged();
      return this;
    }
    /** <code>string attribute_name = 1;</code> */
    public Builder clearAttributeName() {

      attributeName_ = getDefaultInstance().getAttributeName();
      onChanged();
      return this;
    }
    /** <code>string attribute_name = 1;</code> */
    public Builder setAttributeNameBytes(com.google.protobuf.ByteString value) {
      if (value == null) {
        throw new NullPointerException();
      }
      checkByteStringIsUtf8(value);

      attributeName_ = value;
      onChanged();
      return this;
    }

    private Object predicateType_ = "";
    /** <code>string predicate_type = 2;</code> */
    public String getPredicateType() {
      Object ref = predicateType_;
      if (!(ref instanceof String)) {
        com.google.protobuf.ByteString bs = (com.google.protobuf.ByteString) ref;
        String s = bs.toStringUtf8();
        predicateType_ = s;
        return s;
      } else {
        return (String) ref;
      }
    }
    /** <code>string predicate_type = 2;</code> */
    public com.google.protobuf.ByteString getPredicateTypeBytes() {
      Object ref = predicateType_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8((String) ref);
        predicateType_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /** <code>string predicate_type = 2;</code> */
    public Builder setPredicateType(String value) {
      if (value == null) {
        throw new NullPointerException();
      }

      predicateType_ = value;
      onChanged();
      return this;
    }
    /** <code>string predicate_type = 2;</code> */
    public Builder clearPredicateType() {

      predicateType_ = getDefaultInstance().getPredicateType();
      onChanged();
      return this;
    }
    /** <code>string predicate_type = 2;</code> */
    public Builder setPredicateTypeBytes(com.google.protobuf.ByteString value) {
      if (value == null) {
        throw new NullPointerException();
      }
      checkByteStringIsUtf8(value);

      predicateType_ = value;
      onChanged();
      return this;
    }

    private long predicateValue_;
    /** <code>uint64 predicate_value = 3;</code> */
    public long getPredicateValue() {
      return predicateValue_;
    }
    /** <code>uint64 predicate_value = 3;</code> */
    public Builder setPredicateValue(long value) {

      predicateValue_ = value;
      onChanged();
      return this;
    }
    /** <code>uint64 predicate_value = 3;</code> */
    public Builder clearPredicateValue() {

      predicateValue_ = 0L;
      onChanged();
      return this;
    }

    @Override
    public final Builder setUnknownFields(final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.setUnknownFields(unknownFields);
    }

    @Override
    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.mergeUnknownFields(unknownFields);
    }

    // @@protoc_insertion_point(builder_scope:com.webank.wedpr.scd.proto.Predicate)
  }

  // @@protoc_insertion_point(class_scope:com.webank.wedpr.scd.proto.Predicate)
  private static final com.webank.wedpr.scd.proto.Predicate DEFAULT_INSTANCE;

  static {
    DEFAULT_INSTANCE = new com.webank.wedpr.scd.proto.Predicate();
  }

  public static com.webank.wedpr.scd.proto.Predicate getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<Predicate> PARSER =
      new com.google.protobuf.AbstractParser<Predicate>() {
        @Override
        public Predicate parsePartialFrom(
            com.google.protobuf.CodedInputStream input,
            com.google.protobuf.ExtensionRegistryLite extensionRegistry)
            throws com.google.protobuf.InvalidProtocolBufferException {
          return new Predicate(input, extensionRegistry);
        }
      };

  public static com.google.protobuf.Parser<Predicate> parser() {
    return PARSER;
  }

  @Override
  public com.google.protobuf.Parser<Predicate> getParserForType() {
    return PARSER;
  }

  @Override
  public com.webank.wedpr.scd.proto.Predicate getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }
}
