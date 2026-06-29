# libhat Python bindings

Python bindings for [libhat](https://github.com/EpsteinIslandGaming/libhat-rs).

## Usage

> [!NOTE]
> `with` garbage collects the signature and context faster and is deterministic,
> but you don't have to use it in order for the object to be freed.


```python
import hat

# Parse a signature
with hat.parse_signature("48 8D 05 ? ? ? ? E8") as sig:
    # Scan a byte buffer
    data = b"\x00" * 100 + b"\x48\x8D\x05\xBE\x53\x23\x01\xE8" + b"\x00" * 100
    result = hat.find_pattern(sig, data)
    print(f"Match at offset: {result}")  # 100
    
# Or use create_signature for raw bytes with a mask
with hat.create_signature(b"\x48\x8D\x05\x00\x00\x00\x00\xE8", b"\xFF\xFF\xFF\x00\x00\x00\x00\xFF") as sig:
    mod = hat.get_process_module()
    result = hat.find_pattern_mod(sig, mod, ".text")
```

## Building

Build the Rust library first:

```bash
cargo build --release
```

Then use the bindings:
```python
import hat
# or
from hat import * # replace * with whatever you want to import lol
```
