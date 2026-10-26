package datapath;

import go.Seq;
import java.util.Arrays;

/* loaded from: classes.dex */
public final class Session implements Seq.Proxy {
    private final int refnum;

    static {
        Datapath.touch();
    }

    public Session(int i2) {
        this.refnum = i2;
        Seq.trackGoRef(i2, this);
    }

    private static native int __New();

    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Session)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return Arrays.hashCode(new Object[0]);
    }

    @Override // go.Seq.GoObject
    public final int incRefnum() {
        Seq.incGoRef(this.refnum, this);
        return this.refnum;
    }

    public native void setNetwork(long j2);

    public native void stop();

    public String toString() {
        return "Session{}";
    }

    public Session() {
        int __New = __New();
        this.refnum = __New;
        Seq.trackGoRef(__New, this);
    }
}
