package android.system.keystore2;

import android.os.IBinder;
import android.os.IInterface;

import androidx.annotation.Nullable;

public interface IKeystoreOperation extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreOperation";

    @Nullable byte[] updateAad(byte[] aadInput, @Nullable byte[] authToken, @Nullable byte[] timeStampToken);
    @Nullable byte[] update(byte[] input, @Nullable byte[] authToken, @Nullable byte[] timeStampToken);
    @Nullable byte[] finish(@Nullable byte[] input, @Nullable byte[] signature, @Nullable byte[] authToken, @Nullable byte[] timeStampToken);
    void abort();

    class Stub {
        public static IKeystoreOperation asInterface(IBinder b) {
            throw new RuntimeException();
        }
    }
}
