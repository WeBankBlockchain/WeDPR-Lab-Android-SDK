// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: common.proto

package com.webank.wedpr.selectivedisclosure.proto;

/** Protobuf type {@code com.webank.wedpr.selective_disclosure.proto.CredentialInfo} */
public final class CredentialInfo extends com.google.protobuf.GeneratedMessageV3
        implements
        // @@protoc_insertion_point(message_implements:com.webank.wedpr.selective_disclosure.proto.CredentialInfo)
        CredentialInfoOrBuilder {
    private static final long serialVersionUID = 0L;
    // Use CredentialInfo.newBuilder() to construct.
    private CredentialInfo(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
        super(builder);
    }

    private CredentialInfo() {
        attributePair_ = java.util.Collections.emptyList();
    }

    @Override
    @SuppressWarnings({"unused"})
    protected Object newInstance(UnusedPrivateParameter unused) {
        return new CredentialInfo();
    }

    @Override
    public final com.google.protobuf.UnknownFieldSet getUnknownFields() {
        return this.unknownFields;
    }

    private CredentialInfo(
            com.google.protobuf.CodedInputStream input,
            com.google.protobuf.ExtensionRegistryLite extensionRegistry)
            throws com.google.protobuf.InvalidProtocolBufferException {
        this();
        if (extensionRegistry == null) {
            throw new NullPointerException();
        }
        int mutable_bitField0_ = 0;
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
                            if (!((mutable_bitField0_ & 0x00000001) != 0)) {
                                attributePair_ =
                                        new java.util.ArrayList<
                                                StringToStringPair>();
                                mutable_bitField0_ |= 0x00000001;
                            }
                            attributePair_.add(
                                    input.readMessage(
                                            StringToStringPair.parser(),
                                            extensionRegistry));
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
            throw new com.google.protobuf.InvalidProtocolBufferException(e)
                    .setUnfinishedMessage(this);
        } finally {
            if (((mutable_bitField0_ & 0x00000001) != 0)) {
                attributePair_ = java.util.Collections.unmodifiableList(attributePair_);
            }
            this.unknownFields = unknownFields.build();
            makeExtensionsImmutable();
        }
    }

    public static final com.google.protobuf.Descriptors.Descriptor getDescriptor() {
        return Common
                .internal_static_com_webank_wedpr_selective_disclosure_proto_CredentialInfo_descriptor;
    }

    @Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
            internalGetFieldAccessorTable() {
        return Common
                .internal_static_com_webank_wedpr_selective_disclosure_proto_CredentialInfo_fieldAccessorTable
                .ensureFieldAccessorsInitialized(
                        CredentialInfo.class,
                        Builder.class);
    }

    public static final int ATTRIBUTE_PAIR_FIELD_NUMBER = 1;
    private java.util.List<StringToStringPair>
            attributePair_;
    /**
     * <code>
     * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
     * </code>
     */
    public java.util.List<StringToStringPair>
            getAttributePairList() {
        return attributePair_;
    }
    /**
     * <code>
     * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
     * </code>
     */
    public java.util.List<
                    ? extends
                            StringToStringPairOrBuilder>
            getAttributePairOrBuilderList() {
        return attributePair_;
    }
    /**
     * <code>
     * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
     * </code>
     */
    public int getAttributePairCount() {
        return attributePair_.size();
    }
    /**
     * <code>
     * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
     * </code>
     */
    public StringToStringPair getAttributePair(
            int index) {
        return attributePair_.get(index);
    }
    /**
     * <code>
     * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
     * </code>
     */
    public StringToStringPairOrBuilder
            getAttributePairOrBuilder(int index) {
        return attributePair_.get(index);
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
        for (int i = 0; i < attributePair_.size(); i++) {
            output.writeMessage(1, attributePair_.get(i));
        }
        unknownFields.writeTo(output);
    }

    @Override
    public int getSerializedSize() {
        int size = memoizedSize;
        if (size != -1) return size;

        size = 0;
        for (int i = 0; i < attributePair_.size(); i++) {
            size +=
                    com.google.protobuf.CodedOutputStream.computeMessageSize(
                            1, attributePair_.get(i));
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
        if (!(obj instanceof CredentialInfo)) {
            return super.equals(obj);
        }
        CredentialInfo other =
                (CredentialInfo) obj;

        if (!getAttributePairList().equals(other.getAttributePairList())) return false;
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
        if (getAttributePairCount() > 0) {
            hash = (37 * hash) + ATTRIBUTE_PAIR_FIELD_NUMBER;
            hash = (53 * hash) + getAttributePairList().hashCode();
        }
        hash = (29 * hash) + unknownFields.hashCode();
        memoizedHashCode = hash;
        return hash;
    }

    public static CredentialInfo parseFrom(
            java.nio.ByteBuffer data) throws com.google.protobuf.InvalidProtocolBufferException {
        return PARSER.parseFrom(data);
    }

    public static CredentialInfo parseFrom(
            java.nio.ByteBuffer data, com.google.protobuf.ExtensionRegistryLite extensionRegistry)
            throws com.google.protobuf.InvalidProtocolBufferException {
        return PARSER.parseFrom(data, extensionRegistry);
    }

    public static CredentialInfo parseFrom(
            com.google.protobuf.ByteString data)
            throws com.google.protobuf.InvalidProtocolBufferException {
        return PARSER.parseFrom(data);
    }

    public static CredentialInfo parseFrom(
            com.google.protobuf.ByteString data,
            com.google.protobuf.ExtensionRegistryLite extensionRegistry)
            throws com.google.protobuf.InvalidProtocolBufferException {
        return PARSER.parseFrom(data, extensionRegistry);
    }

    public static CredentialInfo parseFrom(byte[] data)
            throws com.google.protobuf.InvalidProtocolBufferException {
        return PARSER.parseFrom(data);
    }

    public static CredentialInfo parseFrom(
            byte[] data, com.google.protobuf.ExtensionRegistryLite extensionRegistry)
            throws com.google.protobuf.InvalidProtocolBufferException {
        return PARSER.parseFrom(data, extensionRegistry);
    }

    public static CredentialInfo parseFrom(
            java.io.InputStream input) throws java.io.IOException {
        return com.google.protobuf.GeneratedMessageV3.parseWithIOException(PARSER, input);
    }

    public static CredentialInfo parseFrom(
            java.io.InputStream input, com.google.protobuf.ExtensionRegistryLite extensionRegistry)
            throws java.io.IOException {
        return com.google.protobuf.GeneratedMessageV3.parseWithIOException(
                PARSER, input, extensionRegistry);
    }

    public static CredentialInfo parseDelimitedFrom(
            java.io.InputStream input) throws java.io.IOException {
        return com.google.protobuf.GeneratedMessageV3.parseDelimitedWithIOException(PARSER, input);
    }

    public static CredentialInfo parseDelimitedFrom(
            java.io.InputStream input, com.google.protobuf.ExtensionRegistryLite extensionRegistry)
            throws java.io.IOException {
        return com.google.protobuf.GeneratedMessageV3.parseDelimitedWithIOException(
                PARSER, input, extensionRegistry);
    }

    public static CredentialInfo parseFrom(
            com.google.protobuf.CodedInputStream input) throws java.io.IOException {
        return com.google.protobuf.GeneratedMessageV3.parseWithIOException(PARSER, input);
    }

    public static CredentialInfo parseFrom(
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

    public static Builder newBuilder(
            CredentialInfo prototype) {
        return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }

    @Override
    public Builder toBuilder() {
        return this == DEFAULT_INSTANCE ? new Builder() : new Builder().mergeFrom(this);
    }

    @Override
    protected Builder newBuilderForType(
            com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        Builder builder = new Builder(parent);
        return builder;
    }
    /** Protobuf type {@code com.webank.wedpr.selective_disclosure.proto.CredentialInfo} */
    public static final class Builder
            extends com.google.protobuf.GeneratedMessageV3.Builder<Builder>
            implements
            // @@protoc_insertion_point(builder_implements:com.webank.wedpr.selective_disclosure.proto.CredentialInfo)
            CredentialInfoOrBuilder {
        public static final com.google.protobuf.Descriptors.Descriptor getDescriptor() {
            return Common
                    .internal_static_com_webank_wedpr_selective_disclosure_proto_CredentialInfo_descriptor;
        }

        @Override
        protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
                internalGetFieldAccessorTable() {
            return Common
                    .internal_static_com_webank_wedpr_selective_disclosure_proto_CredentialInfo_fieldAccessorTable
                    .ensureFieldAccessorsInitialized(
                            CredentialInfo.class,
                            Builder
                                    .class);
        }

        // Construct using com.webank.wedpr.selectivedisclosure.proto.CredentialInfo.newBuilder()
        private Builder() {
            maybeForceBuilderInitialization();
        }

        private Builder(com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
            super(parent);
            maybeForceBuilderInitialization();
        }

        private void maybeForceBuilderInitialization() {
            if (com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders) {
                getAttributePairFieldBuilder();
            }
        }

        @Override
        public Builder clear() {
            super.clear();
            if (attributePairBuilder_ == null) {
                attributePair_ = java.util.Collections.emptyList();
                bitField0_ = (bitField0_ & ~0x00000001);
            } else {
                attributePairBuilder_.clear();
            }
            return this;
        }

        @Override
        public com.google.protobuf.Descriptors.Descriptor getDescriptorForType() {
            return Common
                    .internal_static_com_webank_wedpr_selective_disclosure_proto_CredentialInfo_descriptor;
        }

        @Override
        public CredentialInfo
                getDefaultInstanceForType() {
            return CredentialInfo.getDefaultInstance();
        }

        @Override
        public CredentialInfo build() {
            CredentialInfo result = buildPartial();
            if (!result.isInitialized()) {
                throw newUninitializedMessageException(result);
            }
            return result;
        }

        @Override
        public CredentialInfo buildPartial() {
            CredentialInfo result =
                    new CredentialInfo(this);
            int from_bitField0_ = bitField0_;
            if (attributePairBuilder_ == null) {
                if (((bitField0_ & 0x00000001) != 0)) {
                    attributePair_ = java.util.Collections.unmodifiableList(attributePair_);
                    bitField0_ = (bitField0_ & ~0x00000001);
                }
                result.attributePair_ = attributePair_;
            } else {
                result.attributePair_ = attributePairBuilder_.build();
            }
            onBuilt();
            return result;
        }

        @Override
        public Builder clone() {
            return super.clone();
        }

        @Override
        public Builder setField(
                com.google.protobuf.Descriptors.FieldDescriptor field, Object value) {
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
                com.google.protobuf.Descriptors.FieldDescriptor field,
                int index,
                Object value) {
            return super.setRepeatedField(field, index, value);
        }

        @Override
        public Builder addRepeatedField(
                com.google.protobuf.Descriptors.FieldDescriptor field, Object value) {
            return super.addRepeatedField(field, value);
        }

        @Override
        public Builder mergeFrom(com.google.protobuf.Message other) {
            if (other instanceof CredentialInfo) {
                return mergeFrom((CredentialInfo) other);
            } else {
                super.mergeFrom(other);
                return this;
            }
        }

        public Builder mergeFrom(CredentialInfo other) {
            if (other
                    == CredentialInfo
                            .getDefaultInstance()) return this;
            if (attributePairBuilder_ == null) {
                if (!other.attributePair_.isEmpty()) {
                    if (attributePair_.isEmpty()) {
                        attributePair_ = other.attributePair_;
                        bitField0_ = (bitField0_ & ~0x00000001);
                    } else {
                        ensureAttributePairIsMutable();
                        attributePair_.addAll(other.attributePair_);
                    }
                    onChanged();
                }
            } else {
                if (!other.attributePair_.isEmpty()) {
                    if (attributePairBuilder_.isEmpty()) {
                        attributePairBuilder_.dispose();
                        attributePairBuilder_ = null;
                        attributePair_ = other.attributePair_;
                        bitField0_ = (bitField0_ & ~0x00000001);
                        attributePairBuilder_ =
                                com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders
                                        ? getAttributePairFieldBuilder()
                                        : null;
                    } else {
                        attributePairBuilder_.addAllMessages(other.attributePair_);
                    }
                }
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
            CredentialInfo parsedMessage = null;
            try {
                parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
            } catch (com.google.protobuf.InvalidProtocolBufferException e) {
                parsedMessage =
                        (CredentialInfo)
                                e.getUnfinishedMessage();
                throw e.unwrapIOException();
            } finally {
                if (parsedMessage != null) {
                    mergeFrom(parsedMessage);
                }
            }
            return this;
        }

        private int bitField0_;

        private java.util.List<StringToStringPair>
                attributePair_ = java.util.Collections.emptyList();

        private void ensureAttributePairIsMutable() {
            if (!((bitField0_ & 0x00000001) != 0)) {
                attributePair_ =
                        new java.util.ArrayList<
                                StringToStringPair>(
                                attributePair_);
                bitField0_ |= 0x00000001;
            }
        }

        private com.google.protobuf.RepeatedFieldBuilderV3<
                        StringToStringPair,
                        StringToStringPair.Builder,
                        StringToStringPairOrBuilder>
                attributePairBuilder_;

        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public java.util.List<StringToStringPair>
                getAttributePairList() {
            if (attributePairBuilder_ == null) {
                return java.util.Collections.unmodifiableList(attributePair_);
            } else {
                return attributePairBuilder_.getMessageList();
            }
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public int getAttributePairCount() {
            if (attributePairBuilder_ == null) {
                return attributePair_.size();
            } else {
                return attributePairBuilder_.getCount();
            }
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public StringToStringPair getAttributePair(
                int index) {
            if (attributePairBuilder_ == null) {
                return attributePair_.get(index);
            } else {
                return attributePairBuilder_.getMessage(index);
            }
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public Builder setAttributePair(
                int index, StringToStringPair value) {
            if (attributePairBuilder_ == null) {
                if (value == null) {
                    throw new NullPointerException();
                }
                ensureAttributePairIsMutable();
                attributePair_.set(index, value);
                onChanged();
            } else {
                attributePairBuilder_.setMessage(index, value);
            }
            return this;
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public Builder setAttributePair(
                int index,
                StringToStringPair.Builder
                        builderForValue) {
            if (attributePairBuilder_ == null) {
                ensureAttributePairIsMutable();
                attributePair_.set(index, builderForValue.build());
                onChanged();
            } else {
                attributePairBuilder_.setMessage(index, builderForValue.build());
            }
            return this;
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public Builder addAttributePair(
                StringToStringPair value) {
            if (attributePairBuilder_ == null) {
                if (value == null) {
                    throw new NullPointerException();
                }
                ensureAttributePairIsMutable();
                attributePair_.add(value);
                onChanged();
            } else {
                attributePairBuilder_.addMessage(value);
            }
            return this;
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public Builder addAttributePair(
                int index, StringToStringPair value) {
            if (attributePairBuilder_ == null) {
                if (value == null) {
                    throw new NullPointerException();
                }
                ensureAttributePairIsMutable();
                attributePair_.add(index, value);
                onChanged();
            } else {
                attributePairBuilder_.addMessage(index, value);
            }
            return this;
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public Builder addAttributePair(
                StringToStringPair.Builder
                        builderForValue) {
            if (attributePairBuilder_ == null) {
                ensureAttributePairIsMutable();
                attributePair_.add(builderForValue.build());
                onChanged();
            } else {
                attributePairBuilder_.addMessage(builderForValue.build());
            }
            return this;
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public Builder addAttributePair(
                int index,
                StringToStringPair.Builder
                        builderForValue) {
            if (attributePairBuilder_ == null) {
                ensureAttributePairIsMutable();
                attributePair_.add(index, builderForValue.build());
                onChanged();
            } else {
                attributePairBuilder_.addMessage(index, builderForValue.build());
            }
            return this;
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public Builder addAllAttributePair(
                Iterable<
                                ? extends
                                        StringToStringPair>
                        values) {
            if (attributePairBuilder_ == null) {
                ensureAttributePairIsMutable();
                com.google.protobuf.AbstractMessageLite.Builder.addAll(values, attributePair_);
                onChanged();
            } else {
                attributePairBuilder_.addAllMessages(values);
            }
            return this;
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public Builder clearAttributePair() {
            if (attributePairBuilder_ == null) {
                attributePair_ = java.util.Collections.emptyList();
                bitField0_ = (bitField0_ & ~0x00000001);
                onChanged();
            } else {
                attributePairBuilder_.clear();
            }
            return this;
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public Builder removeAttributePair(int index) {
            if (attributePairBuilder_ == null) {
                ensureAttributePairIsMutable();
                attributePair_.remove(index);
                onChanged();
            } else {
                attributePairBuilder_.remove(index);
            }
            return this;
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public StringToStringPair.Builder
                getAttributePairBuilder(int index) {
            return getAttributePairFieldBuilder().getBuilder(index);
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public StringToStringPairOrBuilder
                getAttributePairOrBuilder(int index) {
            if (attributePairBuilder_ == null) {
                return attributePair_.get(index);
            } else {
                return attributePairBuilder_.getMessageOrBuilder(index);
            }
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public java.util.List<
                        ? extends
                                StringToStringPairOrBuilder>
                getAttributePairOrBuilderList() {
            if (attributePairBuilder_ != null) {
                return attributePairBuilder_.getMessageOrBuilderList();
            } else {
                return java.util.Collections.unmodifiableList(attributePair_);
            }
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public StringToStringPair.Builder
                addAttributePairBuilder() {
            return getAttributePairFieldBuilder()
                    .addBuilder(
                            StringToStringPair
                                    .getDefaultInstance());
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public StringToStringPair.Builder
                addAttributePairBuilder(int index) {
            return getAttributePairFieldBuilder()
                    .addBuilder(
                            index,
                            StringToStringPair
                                    .getDefaultInstance());
        }
        /**
         * <code>
         * repeated .com.webank.wedpr.selective_disclosure.proto.StringToStringPair attribute_pair = 1;
         * </code>
         */
        public java.util.List<StringToStringPair.Builder>
                getAttributePairBuilderList() {
            return getAttributePairFieldBuilder().getBuilderList();
        }

        private com.google.protobuf.RepeatedFieldBuilderV3<
                        StringToStringPair,
                        StringToStringPair.Builder,
                        StringToStringPairOrBuilder>
                getAttributePairFieldBuilder() {
            if (attributePairBuilder_ == null) {
                attributePairBuilder_ =
                        new com.google.protobuf.RepeatedFieldBuilderV3<
                                StringToStringPair,
                                StringToStringPair
                                        .Builder,
                                StringToStringPairOrBuilder>(
                                attributePair_,
                                ((bitField0_ & 0x00000001) != 0),
                                getParentForChildren(),
                                isClean());
                attributePair_ = null;
            }
            return attributePairBuilder_;
        }

        @Override
        public final Builder setUnknownFields(
                final com.google.protobuf.UnknownFieldSet unknownFields) {
            return super.setUnknownFields(unknownFields);
        }

        @Override
        public final Builder mergeUnknownFields(
                final com.google.protobuf.UnknownFieldSet unknownFields) {
            return super.mergeUnknownFields(unknownFields);
        }

        // @@protoc_insertion_point(builder_scope:com.webank.wedpr.selective_disclosure.proto.CredentialInfo)
    }

    // @@protoc_insertion_point(class_scope:com.webank.wedpr.selective_disclosure.proto.CredentialInfo)
    private static final CredentialInfo DEFAULT_INSTANCE;

    static {
        DEFAULT_INSTANCE = new CredentialInfo();
    }

    public static CredentialInfo getDefaultInstance() {
        return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<CredentialInfo> PARSER =
            new com.google.protobuf.AbstractParser<CredentialInfo>() {
                @Override
                public CredentialInfo parsePartialFrom(
                        com.google.protobuf.CodedInputStream input,
                        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
                        throws com.google.protobuf.InvalidProtocolBufferException {
                    return new CredentialInfo(input, extensionRegistry);
                }
            };

    public static com.google.protobuf.Parser<CredentialInfo> parser() {
        return PARSER;
    }

    @Override
    public com.google.protobuf.Parser<CredentialInfo> getParserForType() {
        return PARSER;
    }

    @Override
    public CredentialInfo getDefaultInstanceForType() {
        return DEFAULT_INSTANCE;
    }
}
