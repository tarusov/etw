// +build windows
// +build !winxp

#include "provider.h"

const DWORD MAX_LPWSTR_SIZE = 0xFF;

DWORD EnumerateProviders(
    ETW_PROVIDER_INFO *providers,
     ULONG *count)
{
    DWORD status = ERROR_SUCCESS;

    // Retrieve the required buffer size for the first time.
    PROVIDER_ENUMERATION_INFO *penum = NULL;
    DWORD bufferSize = 0;
    status = TdhEnumerateProviders(penum, &bufferSize);

    // Allocate buffer and try to get providers.

    PROVIDER_ENUMERATION_INFO *ptemp = NULL;
    while (status == ERROR_INSUFFICIENT_BUFFER)
    {
        ptemp = (PROVIDER_ENUMERATION_INFO *)realloc(penum, bufferSize);
        if (ptemp == NULL)
        {
            status = GetLastError();
            goto cleanup;
        }

        penum = ptemp;
        ptemp = NULL;

        status = TdhEnumerateProviders(penum, &bufferSize);
    }

    if (status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    // Fill structs with provider name and guid.

    *count = penum->NumberOfProviders;

    for (DWORD i = 0; i < penum->NumberOfProviders; i++)
    {
        LPWSTR nameSrc = (LPWSTR)((PBYTE)(penum) + penum->TraceProviderInfoArray[i].ProviderNameOffset);
        DWORD nameSize = wcsnlen(nameSrc, MAX_LPWSTR_SIZE) + 1; // Inc by one, because \0 at the end.
        LPWSTR name = malloc(nameSize * sizeof(WCHAR));
        wcscpy_s(name, nameSize, nameSrc);

        providers[i].ProviderName = name;
        providers[i].ProviderGuid = penum->TraceProviderInfoArray[i].ProviderGuid;
    }

cleanup:

    if (penum)
    {
        free(penum);
        penum = NULL;
    }

    return status;
}

DWORD EnumerateProviderKeywords(
    LPGUID pGuid,
    ETW_KEYWORD_INFO *keywords,
    ULONG *count)
{
    DWORD status = ERROR_SUCCESS;

    // Retrieve the required buffer size for the first time.
    PPROVIDER_FIELD_INFOARRAY penum = NULL;
    DWORD bufferSize = 0;
    status = TdhEnumerateProviderFieldInformation(
        pGuid,
        EventKeywordInformation,
        penum,
        &bufferSize);

    // Allocate buffer and try to get provider property info.

    PPROVIDER_FIELD_INFOARRAY ptemp = NULL;
    while (status == ERROR_INSUFFICIENT_BUFFER)
    {
        ptemp = (PPROVIDER_FIELD_INFOARRAY)realloc(penum, bufferSize);
        if (ptemp == NULL)
        {
            status = GetLastError();
            goto cleanup;
        }

        penum = ptemp;
        ptemp = NULL;

        status = TdhEnumerateProviderFieldInformation(
            pGuid,
            EventKeywordInformation,
            penum,
            &bufferSize);
    }

    if (status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    // Fill structs with provider name and guid.

    *count = penum->NumberOfElements;

    for (DWORD i = 0; i < penum->NumberOfElements; i++)
    {
        LPWSTR nameSrc = (LPWSTR)((PBYTE)(penum) + penum->FieldInfoArray[i].NameOffset);
        DWORD nameSize = wcsnlen(nameSrc, MAX_LPWSTR_SIZE) + 1; // Inc by one, because \0 at the end.
        LPWSTR name = malloc(nameSize * sizeof(WCHAR));
        wcscpy_s(name, nameSize, nameSrc);

        keywords[i].Name = name;
        keywords[i].Value = penum->FieldInfoArray[i].Value;
    }

cleanup:

    if (penum)
    {
        free(penum);
        penum = NULL;
    }

    return status;
}
