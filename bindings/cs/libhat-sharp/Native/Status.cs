/// <summary>Matches libhat::c::LibhatStatus.</summary>
namespace Hat.Native;

internal enum Status
{
	Success = 0,
	ErrUnknown = 1,
	SigInvalid = 2,
	SigEmpty = 3,
	SigNoByte = 4,
}
