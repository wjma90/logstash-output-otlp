package org.otlp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

record OtlpPartialSuccess(long rejectedLogRecords, String errorMessage) {
    private static final int MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
    private static final int MAX_MESSAGE_BYTES = 1024;

    static OtlpPartialSuccess parse(byte[] response) {
        if (response.length > MAX_RESPONSE_BYTES) throw invalidResponse();
        ByteBuffer input = ByteBuffer.wrap(response);
        long rejected = 0;
        String message = "";
        while (input.hasRemaining()) {
            int tag = readTag(input);
            if (tag != 10) {
                skip(input, tag);
                continue;
            }
            int length = readLength(input);
            ByteBuffer partial = input.slice();
            partial.limit(length);
            input.position(input.position() + length);
            while (partial.hasRemaining()) {
                int field = readTag(partial);
                if (field == 8) {
                    rejected = readVarint(partial);
                    if (rejected < 0) throw invalidResponse();
                } else if (field == 18) {
                    int messageLength = readLength(partial);
                    int kept = Math.min(messageLength, MAX_MESSAGE_BYTES);
                    message = new String(response, partial.arrayOffset() + partial.position(), kept,
                            StandardCharsets.UTF_8);
                    if (kept < messageLength) message += "...";
                    partial.position(partial.position() + messageLength);
                } else {
                    skip(partial, field);
                }
            }
        }
        return new OtlpPartialSuccess(rejected, message);
    }

    private static int readTag(ByteBuffer input) {
        long tag = readVarint(input);
        if (tag < 8 || tag > 0xffffffffL) throw invalidResponse();
        return (int) tag;
    }

    private static long readVarint(ByteBuffer input) {
        long value = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            if (!input.hasRemaining()) throw invalidResponse();
            int next = input.get() & 0xff;
            if (shift == 63 && next > 1) throw invalidResponse();
            value |= (long) (next & 0x7f) << shift;
            if ((next & 0x80) == 0) return value;
        }
        throw invalidResponse();
    }

    private static int readLength(ByteBuffer input) {
        long length = readVarint(input);
        if (length < 0 || length > input.remaining()) throw invalidResponse();
        return (int) length;
    }

    private static void skip(ByteBuffer input, int tag) {
        skip(input, tag, 0);
    }

    private static void skip(ByteBuffer input, int tag, int depth) {
        if (depth > 32) throw invalidResponse();
        int length;
        switch (tag & 7) {
            case 0:
                readVarint(input);
                return;
            case 1:
                length = 8;
                break;
            case 2:
                length = readLength(input);
                break;
            case 3:
                while (input.hasRemaining()) {
                    int nested = readTag(input);
                    if ((nested & 7) == 4) {
                        if ((nested >>> 3) != (tag >>> 3)) throw invalidResponse();
                        return;
                    }
                    skip(input, nested, depth + 1);
                }
                throw invalidResponse();
            case 5:
                length = 4;
                break;
            default:
                throw invalidResponse();
        }
        if (length > input.remaining()) throw invalidResponse();
        input.position(input.position() + length);
    }

    private static IllegalArgumentException invalidResponse() {
        return new IllegalArgumentException("Invalid OTLP logs response");
    }
}
