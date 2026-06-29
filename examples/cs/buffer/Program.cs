using System.Runtime.InteropServices;
using Hat;
using Hat.Extensions;

var randomBytes = new byte[0x10000];
new Random().NextBytes(randomBytes);

var pattern = randomBytes.AsSpan().Slice(0x1000, 0x10).ToArray().AsPattern();
var scanner = new Scanner(Marshal.UnsafeAddrOfPinnedArrayElement(randomBytes, 0), (uint)randomBytes.Length);
var address = scanner.FindPattern(pattern);

Console.WriteLine($"Buffer: Found pattern at 0x{address:X}");
