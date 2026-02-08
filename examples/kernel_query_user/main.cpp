#include <scfw/runtime.h>
#include <scfw/platform/windows/kernelmode.h>

extern "C" {

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define DPFLTR_IHVDRIVER_ID     77
#define DPFLTR_ERROR_LEVEL      0

#define KSECDDDECLSPEC
#define SEC_ENTRY               __stdcall

//////////////////////////////////////////////////////////////////////////
// Internal Structures.
//////////////////////////////////////////////////////////////////////////

typedef CCHAR KPROCESSOR_MODE;
typedef struct _ACCESS_STATE* PACCESS_STATE;
typedef struct _EPROCESS* PEPROCESS, *PKPROCESS, *PRKPROCESS;
typedef struct _OBJECT_TYPE* POBJECT_TYPE;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

typedef _Enum_is_bitflag_ enum _POOL_TYPE {
    NonPagedPool,
} POOL_TYPE;

//////////////////////////////////////////////////////////////////////////
// Function prototypes.
//////////////////////////////////////////////////////////////////////////

//
// Dbg
//

NTSYSAPI
ULONG
__cdecl
DbgPrintEx (
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );

//
// Ex
//

NTKERNELAPI
PVOID
NTAPI
ExAllocatePoolWithTag (
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExFreePoolWithTag (
    _Pre_notnull_ __drv_freesMem(Mem) PVOID P,
    _In_ ULONG Tag
    );

//
// Ob
//

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer (
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
    );

NTKERNELAPI
NTSTATUS
ObCloseHandle (
    _In_ _Post_ptr_invalid_ HANDLE Handle,
    _In_ KPROCESSOR_MODE PreviousMode
    );

//
// Ps
//

_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
PACCESS_TOKEN
PsReferencePrimaryToken (
    _Inout_ PEPROCESS Process
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTKERNELAPI
VOID
PsDereferencePrimaryToken (
    _In_ PACCESS_TOKEN PrimaryToken
    );

//
// Rtl
//

_IRQL_requires_max_(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlConvertSidToUnicodeString (
    _Inout_ PUNICODE_STRING UnicodeString,
    _In_ PSID Sid,
    _In_ BOOLEAN AllocateDestinationString
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlFreeUnicodeString (
    _Inout_ _At_(UnicodeString->Buffer, _Frees_ptr_opt_)
        PUNICODE_STRING UnicodeString
    );

//
// Sec
//

KSECDDDECLSPEC
NTSTATUS
SEC_ENTRY
SecLookupAccountSid (
    _In_      PSID Sid,
    _Out_     PULONG NameSize,
    _Inout_   PUNICODE_STRING NameBuffer,
    _Out_     PULONG DomainSize OPTIONAL,
    _Out_opt_ PUNICODE_STRING DomainBuffer OPTIONAL,
    _Out_     PSID_NAME_USE NameUse
    );

} // extern "C"

IMPORT_BEGIN();
    IMPORT_MODULE("ntoskrnl.exe");
        IMPORT_SYMBOL(DbgPrintEx);
        IMPORT_SYMBOL(ExAllocatePoolWithTag);
        IMPORT_SYMBOL(ExFreePoolWithTag);
        IMPORT_SYMBOL(ObOpenObjectByPointer);
        IMPORT_SYMBOL(ObCloseHandle);
        IMPORT_SYMBOL(PsReferencePrimaryToken);
        IMPORT_SYMBOL(PsDereferencePrimaryToken);
        IMPORT_SYMBOL(RtlConvertSidToUnicodeString);
        IMPORT_SYMBOL(RtlFreeUnicodeString);
        IMPORT_SYMBOL(ZwQueryInformationToken);
        IMPORT_SYMBOL(SeTokenObjectType, POBJECT_TYPE*);

    IMPORT_MODULE("ksecdd.sys");
        IMPORT_SYMBOL(SecLookupAccountSid);
IMPORT_END();

namespace sc {

#define SHELLCODE_MEMORY_TAG    'wfcs'

NTSTATUS
QueryUserInformation(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING UserName,
    _Out_ PUNICODE_STRING DomainName,
    _Out_ PUNICODE_STRING Sid
    )
{
    NTSTATUS Status;

    //
    // Get the primary token of the process, and open a handle to it.
    //

    PACCESS_TOKEN AccessToken;
    AccessToken = PsReferencePrimaryToken(Process);

    if (!AccessToken)
    {
        return STATUS_NO_TOKEN;
    }

    HANDLE TokenHandle;
    Status = ObOpenObjectByPointer(AccessToken,
                                   0,
                                   NULL,
                                   TOKEN_ALL_ACCESS,
                                   *SeTokenObjectType,
                                   (KPROCESSOR_MODE)KernelMode,
                                   &TokenHandle);

    PsDereferencePrimaryToken(AccessToken);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    //
    // Query the token for the user SID.
    //

    ULONG ReturnLength;
    SE_TOKEN_USER TokenUserInformation;
    Status = ZwQueryInformationToken(TokenHandle,
                                     TokenUser,
                                     &TokenUserInformation,
                                     static_cast<ULONG>(sizeof(TokenUserInformation)),
                                     &ReturnLength);

    ObCloseHandle(TokenHandle, KernelMode);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    //
    // Convert the user SID to a Unicode string.
    // N.B. The caller is responsible for freeing the SID string buffer.
    //

    Status = RtlConvertSidToUnicodeString(Sid,
                                          TokenUserInformation.User.Sid,
                                          TRUE);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ULONG UserNameLength = 0;
    PVOID UserNameBuffer = NULL;

    ULONG DomainNameLength = 0;
    PVOID DomainNameBuffer = NULL;

    do
    {
        if (UserNameLength)
        {
            UserNameBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                                   UserNameLength,
                                                   SHELLCODE_MEMORY_TAG);

            if (!UserNameBuffer)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
        }

        if (DomainNameLength)
        {
            DomainNameBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                                     DomainNameLength,
                                                     SHELLCODE_MEMORY_TAG);

            if (!DomainNameBuffer)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
        }

        UserName->Length = 0;
        UserName->MaximumLength = (USHORT)UserNameLength;
        UserName->Buffer = (PWCHAR)UserNameBuffer;

        DomainName->Length = 0;
        DomainName->MaximumLength = (USHORT)DomainNameLength;
        DomainName->Buffer = (PWCHAR)DomainNameBuffer;

        SID_NAME_USE NameUse;
        Status = SecLookupAccountSid(&TokenUserInformation.Sid,
                                     &UserNameLength,
                                     UserName,
                                     &DomainNameLength,
                                     DomainName,
                                     &NameUse);

    } while (Status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(Status))
    {
        if (DomainNameBuffer)
        {
            ExFreePoolWithTag(DomainNameBuffer, SHELLCODE_MEMORY_TAG);
        }

        if (UserNameBuffer)
        {
            ExFreePoolWithTag(UserNameBuffer, SHELLCODE_MEMORY_TAG);
        }

        UserName->Length = 0;
        UserName->MaximumLength = 0;
        UserName->Buffer = NULL;

        DomainName->Length = 0;
        DomainName->MaximumLength = 0;
        DomainName->Buffer = NULL;
    }

    return Status;
}

extern "C" void __fastcall entry(void* argument1, void* argument2)
{
    (void)argument1; // Kernel ImageBase, unused in this example.

    NTSTATUS Status;

    PEPROCESS Process = (PEPROCESS)argument2;

    UNICODE_STRING UserName;
    UNICODE_STRING DomainName;
    UNICODE_STRING Sid;

    Status = QueryUserInformation(Process, &UserName, &DomainName, &Sid);

    if (!NT_SUCCESS(Status))
    {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_ERROR_LEVEL,
               "DomainName: '%wZ'\n"
               "UserName: '%wZ'\n"
               "SID: %wZ\n",
                   &DomainName,
                   &UserName,
                   &Sid);

    RtlFreeUnicodeString(&Sid);
    RtlFreeUnicodeString(&DomainName);
    RtlFreeUnicodeString(&UserName);
}

}
