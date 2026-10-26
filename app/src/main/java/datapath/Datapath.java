package datapath;

import go.Seq;

/* loaded from: classes.dex */
public abstract class Datapath {
    static {
        Seq.touch();
        _init();
    }

    private Datapath() {
    }

    private static native void _init();

    public static native Session start(long j2, long j3);

    public static void touch() {
    }
}
