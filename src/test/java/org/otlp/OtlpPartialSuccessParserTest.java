package org.otlp;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OtlpPartialSuccessParserTest {
    @Test
    void readsRejectedCountAndMessageWithoutChangingTheResponse() {
        byte[] response = {10, 8, 8, (byte) 0xac, 2, 18, 3, 'b', 'a', 'd'};
        byte[] original = response.clone();

        assertEquals(new OtlpPartialSuccess(300, "bad"), OtlpPartialSuccess.parse(response));
        assertArrayEquals(original, response);
    }

    @Test
    void acceptsFullSuccessAndWarningWithoutRejections() {
        for (byte[] response : List.of(new byte[0], new byte[]{10, 0})) {
            assertEquals(new OtlpPartialSuccess(0, ""), OtlpPartialSuccess.parse(response));
        }
        assertEquals(new OtlpPartialSuccess(0, "old"),
                OtlpPartialSuccess.parse(new byte[]{10, 5, 18, 3, 'o', 'l', 'd'}));
    }

    @Test
    void skipsUnknownFieldsAndMergesRepeatedPartialMessages() {
        byte[] response = {16, 5, 35, 43, 8, 1, 44, 36, 10, 7, 8, 2, 26, 3, 1, 2, 3,
                10, 5, 18, 3, 'b', 'a', 'd', 29, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 0};

        assertEquals(new OtlpPartialSuccess(2, "bad"), OtlpPartialSuccess.parse(response));
    }

    @Test
    void rejectsMalformedLengthsTagsAndCounts() {
        for (byte[] response : List.of(
                new byte[]{10}, new byte[]{10, 3, 8, 1}, new byte[]{10, 1, 8},
                new byte[]{0}, new byte[]{10, 2, 8, (byte) 0x80},
                new byte[]{10, 11, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1},
                new byte[]{10, 11, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2},
                new byte[]{10, 2, 18, 5}, new byte[]{25, 0}, new byte[]{35}, new byte[]{35, 44})) {
            assertThrows(IllegalArgumentException.class, () -> OtlpPartialSuccess.parse(response));
        }
    }

    @Test
    void boundsTheDiagnosticMessageAndRejectsOversizedResponses() {
        byte[] response = new byte[2054];
        response[0] = 10;
        response[1] = (byte) 0x83;
        response[2] = 0x10;
        response[3] = 18;
        response[4] = (byte) 0x80;
        response[5] = 0x10;
        java.util.Arrays.fill(response, 6, response.length, (byte) 'a');

        assertEquals("a".repeat(1024) + "...", OtlpPartialSuccess.parse(response).errorMessage());
        assertThrows(IllegalArgumentException.class, () -> OtlpPartialSuccess.parse(new byte[4 * 1024 * 1024 + 1]));
        byte[] nestedGroups = new byte[100];
        java.util.Arrays.fill(nestedGroups, (byte) 35);
        assertThrows(IllegalArgumentException.class, () -> OtlpPartialSuccess.parse(nestedGroups));
    }
}
