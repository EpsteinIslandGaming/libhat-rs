using Hat.Native;

namespace Hat;

internal static class Utils
{
    internal static void CheckStatus(Status status)
    {
        if (status == Status.Success) return;
        
        throw status switch
        {
            Status.SigEmpty => new ArgumentException("Signature is empty."),
            Status.SigInvalid => new ArgumentException("Signature is invalid."),
            Status.SigNoByte => new ArgumentException("Signature contains no bytes, or only contains wildcards."),
            Status.ErrUnknown => new InvalidOperationException("Unknown error occurred."),
            _ => new ArgumentOutOfRangeException()
        };
    }
}