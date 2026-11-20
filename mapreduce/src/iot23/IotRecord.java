package iot23;

/**
 * Parses one line of the preprocessed IoT-23 TSV
 * (see docs/module1_data_dictionary.md for the column layout).
 */
public class IotRecord {
    public static final int TS = 0;
    public static final int UID = 1;
    public static final int SRC_IP = 2;
    public static final int SRC_PORT = 3;
    public static final int DST_IP = 4;
    public static final int DST_PORT = 5;
    public static final int PROTO = 6;
    public static final int SERVICE = 7;
    public static final int DURATION = 8;
    public static final int ORIG_BYTES = 9;
    public static final int RESP_BYTES = 10;
    public static final int CONN_STATE = 11;
    public static final int LOCAL_ORIG = 12;
    public static final int LOCAL_RESP = 13;
    public static final int MISSED_BYTES = 14;
    public static final int HISTORY = 15;
    public static final int ORIG_PKTS = 16;
    public static final int ORIG_IP_BYTES = 17;
    public static final int RESP_PKTS = 18;
    public static final int RESP_IP_BYTES = 19;
    public static final int TUNNEL_PARENTS = 20;
    public static final int LABEL = 21;
    public static final int DETAILED_LABEL = 22;
    public static final int SCENARIO = 23;
    public static final int NUM_FIELDS = 24;

    private final String[] fields;

    private IotRecord(String[] fields) {
        this.fields = fields;
    }

    /** Returns null for header lines or rows that don't have the expected column count. */
    public static IotRecord parse(String line) {
        if (line == null || line.isEmpty()) {
            return null;
        }
        String[] fields = line.split("\t", -1);
        if (fields.length != NUM_FIELDS) {
            return null;
        }
        if (fields[TS].equals("ts")) {
            return null; // header row repeated at the top of every per-scenario file
        }
        return new IotRecord(fields);
    }

    public String get(int index) {
        return fields[index];
    }

    /** Returns 0 for missing/unparseable numeric fields rather than throwing. */
    public long getLong(int index) {
        String v = fields[index];
        if (v == null || v.isEmpty() || v.equals("-")) {
            return 0L;
        }
        try {
            return Long.parseLong(v);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    /**
     * orig_bytes/resp_bytes are Zeek's reassembled application-payload byte counts; they can
     * never legitimately exceed the corresponding IP-layer byte counts (which include every
     * packet, headers included). Zeek occasionally logs a bogus, wildly inflated orig_bytes/
     * resp_bytes on connections with sequence-number gaps (conn_state OTH); treat those as
     * invalid rather than letting one row dominate a sum over millions of flows.
     */
    private long sanitizedAppBytes(int appBytesIdx, int ipBytesIdx) {
        long appBytes = getLong(appBytesIdx);
        long ipBytes = getLong(ipBytesIdx);
        return appBytes > ipBytes ? 0L : appBytes;
    }

    public long totalBytes() {
        return sanitizedAppBytes(ORIG_BYTES, ORIG_IP_BYTES) + sanitizedAppBytes(RESP_BYTES, RESP_IP_BYTES);
    }
}
