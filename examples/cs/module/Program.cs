using System.Diagnostics;
using Hat;

var modulePattern = new Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 81 EC");
var module = Process.GetCurrentProcess().MainModule!;
var moduleScanner = new Scanner(module);
var moduleAddress = moduleScanner.FindPattern(modulePattern);

Console.WriteLine($"Module: Found pattern at 0x{moduleAddress:X}");
