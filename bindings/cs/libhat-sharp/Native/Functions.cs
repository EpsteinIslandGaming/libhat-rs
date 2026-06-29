using System.Runtime.InteropServices;

namespace Hat.Native;

internal static unsafe partial class Functions
{
	/// <summary>
	/// The native shared library name.
	/// Build with: cargo build --release --lib
	/// | OS                  | File Name      |
    /// |---------------------|----------------|
    /// | Windows             | `hat.dll`      |
    /// | Linux               | `libhat.so`    |
    /// | MacOS               | `libhat.dylib` |
	/// </summary>
	private const string LIBRARY_NAME = "hat";
	
	[LibraryImport(LIBRARY_NAME)]
	internal static partial Status libhat_parse_signature(
		[MarshalAs(UnmanagedType.LPStr)] string signatureStr, out Signature* signature);
	
	[LibraryImport(LIBRARY_NAME)]
	internal static partial Status libhat_create_signature(byte[] bytes, byte[] mask, uint size, out Signature* signature);
	
	[LibraryImport(LIBRARY_NAME)]
	internal static partial nint libhat_find_pattern(Signature* signature, nint buffer, uint size, ScanAlignment align);
	
	[LibraryImport(LIBRARY_NAME)]
	internal static partial nint libhat_find_pattern_mod(Signature* signature, nint module, 
		[MarshalAs(UnmanagedType.LPStr)] string section, ScanAlignment align);

	[LibraryImport(LIBRARY_NAME)]
	internal static partial void libhat_free(nint data);
}
