import me.zero.libhat.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.OptionalInt;

public class HatExample {
    public static void main(String[] args) {
        byte[] data = new byte[] {
            0x00, 0x48, (byte)0x8D, 0x05, (byte)0xBE, 0x53, 0x23, 0x01, (byte)0xE8, 0x00
        };
        ByteBuffer buf = ByteBuffer.allocateDirect(data.length);
        buf.put(data);
        buf.flip();

        OptionalInt result = Hat.findPattern("48 8D 05 ? ? ? ? E8", buf);
        if (result.isPresent()) {
            System.out.println("Buffer: Found at offset " + result.getAsInt());
        } else {
            System.out.println("Buffer: Not found");
        }

        ProcessModule mod = Hat.getProcessModule();
        try (Signature sig = Hat.parseSignature("48 89 5C 24 ? 48 89 6C 24 ?")) {
            var ptr = Hat.findPattern(sig, mod, ".text");
            ptr.ifPresentOrElse(
                p -> System.out.println("Module: Found at " + p),
                () -> System.out.println("Module: Not found")
            );
        }
    }
}
