// Copyright 2019 ayumax. All Rights Reserved.
#include "OpenSSL/OpenSslConnection.h"
#include "Sockets.h"
#include "SocketSubsystem.h"
#include "HAL/PlatformMisc.h"
#include "HAL/PlatformProcess.h"
#include "HAL/PlatformTime.h"
#include "HAL/PlatformFileManager.h"
#include "HAL/Runnable.h"
#include "HAL/RunnableThread.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "Misc/ScopeLock.h"
#include "Interfaces/ISslCertificateManager.h"
#include "SslModule.h"

#if PLATFORM_WINDOWS
#include "Windows/AllowWindowsPlatformTypes.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include "Windows/HideWindowsPlatformTypes.h"
#else
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#endif

#ifdef UI
	#pragma push_macro("UI")
	#undef UI
	#define OBJECTDELIVERER_RESTORE_UI 1
#endif

#define UI UE_OPENSSL_UI
#define OBJECTDELIVERER_UNDEF_OPENSSL_UI 1

#include "openssl/ssl.h"
#include "openssl/err.h"

// SE_EPIPE is not defined in UE 5.7 yet, use SE_ECONNRESET as equivalent on Unix/Mac
// Broken pipe errors are reported as ECONNRESET on most Unix-like systems
#ifndef SE_EPIPE
#define SE_EPIPE SE_ECONNRESET
#endif

// On macOS, EPIPE (error 32) is returned but may not be mapped to SE_ECONNRESET
// Define a constant for the macOS EPIPE error code (32)
#if PLATFORM_MAC || PLATFORM_UNIX
#define MACOS_EPIPE_ERROR_CODE 32
#endif
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"
#include "openssl/x509v3.h"
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/bio.h"

#ifdef OBJECTDELIVERER_UNDEF_OPENSSL_UI
	#undef UI
	#undef OBJECTDELIVERER_UNDEF_OPENSSL_UI
#endif

#ifdef OBJECTDELIVERER_RESTORE_UI
	#pragma pop_macro("UI")
	#undef OBJECTDELIVERER_RESTORE_UI
#endif
#include <errno.h>
#include <cstring>
#include <cstdlib>
#include "Utils/ODLog.h"

namespace
{
	FString NormalizeOpenSslPathForExternalRead(const FString& InPath)
	{
		FString OutPath = IFileManager::Get().ConvertToAbsolutePathForExternalAppForRead(*InPath);
		FPaths::NormalizeFilename(OutPath);
		return OutPath;
	}

#if PLATFORM_ANDROID
	FString NormalizeOpenSslPathForAndroid(const FString& InPath)
	{
		return NormalizeOpenSslPathForExternalRead(InPath);
	}

	FString GetOpenSslQueueErrorString()
	{
		const unsigned long ErrCode = ERR_get_error();
		if (ErrCode == 0)
		{
			return TEXT("unknown OpenSSL error");
		}

		char ErrMsg[256];
		ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
		return UTF8_TO_TCHAR(ErrMsg);
	}

	bool LoadPemBytesForAndroid(const FString& InPath, TArray<uint8>& OutBytes, FString& OutNormalizedPath, FString& OutReason)
	{
		OutNormalizedPath = NormalizeOpenSslPathForAndroid(InPath);
		if (!FFileHelper::LoadFileToArray(OutBytes, *OutNormalizedPath))
		{
			OutReason = TEXT("file read failed");
			return false;
		}

		if (OutBytes.Num() == 0)
		{
			OutReason = TEXT("file is empty");
			return false;
		}

		return true;
	}

	bool UseCertificatePemFileAndroid(SSL_CTX* InSslCtx, const FString& InPath, FString& OutReason)
	{
		TArray<uint8> PemBytes;
		FString NormalizedPath;
		if (!LoadPemBytesForAndroid(InPath, PemBytes, NormalizedPath, OutReason))
		{
			return false;
		}

		BIO* CertBio = BIO_new_mem_buf(PemBytes.GetData(), PemBytes.Num());
		if (!CertBio)
		{
			OutReason = TEXT("failed to create memory BIO");
			return false;
		}

		X509* Cert = PEM_read_bio_X509(CertBio, nullptr, nullptr, nullptr);
		BIO_free(CertBio);
		if (!Cert)
		{
			OutReason = FString::Printf(TEXT("PEM parse failed: %s"), *GetOpenSslQueueErrorString());
			return false;
		}

		const int UseResult = SSL_CTX_use_certificate(InSslCtx, Cert);
		X509_free(Cert);
		if (UseResult != 1)
		{
			OutReason = FString::Printf(TEXT("SSL_CTX_use_certificate failed: %s"), *GetOpenSslQueueErrorString());
			return false;
		}

		return true;
	}

	bool UsePrivateKeyPemFileAndroid(SSL_CTX* InSslCtx, const FString& InPath, FString& OutReason)
	{
		TArray<uint8> PemBytes;
		FString NormalizedPath;
		if (!LoadPemBytesForAndroid(InPath, PemBytes, NormalizedPath, OutReason))
		{
			return false;
		}

		BIO* KeyBio = BIO_new_mem_buf(PemBytes.GetData(), PemBytes.Num());
		if (!KeyBio)
		{
			OutReason = TEXT("failed to create memory BIO");
			return false;
		}

		EVP_PKEY* PrivateKey = PEM_read_bio_PrivateKey(KeyBio, nullptr, nullptr, nullptr);
		BIO_free(KeyBio);
		if (!PrivateKey)
		{
			OutReason = FString::Printf(TEXT("PEM parse failed: %s"), *GetOpenSslQueueErrorString());
			return false;
		}

		const int UseResult = SSL_CTX_use_PrivateKey(InSslCtx, PrivateKey);
		EVP_PKEY_free(PrivateKey);
		if (UseResult != 1)
		{
			OutReason = FString::Printf(TEXT("SSL_CTX_use_PrivateKey failed: %s"), *GetOpenSslQueueErrorString());
			return false;
		}

		return true;
	}

	bool LoadTrustedCaPemFileAndroid(SSL_CTX* InSslCtx, const FString& InPath, FString& OutReason)
	{
		TArray<uint8> PemBytes;
		FString NormalizedPath;
		if (!LoadPemBytesForAndroid(InPath, PemBytes, NormalizedPath, OutReason))
		{
			return false;
		}

		BIO* CaBio = BIO_new_mem_buf(PemBytes.GetData(), PemBytes.Num());
		if (!CaBio)
		{
			OutReason = TEXT("failed to create memory BIO");
			return false;
		}

		X509* CaCert = PEM_read_bio_X509(CaBio, nullptr, nullptr, nullptr);
		BIO_free(CaBio);
		if (!CaCert)
		{
			OutReason = FString::Printf(TEXT("PEM parse failed: %s"), *GetOpenSslQueueErrorString());
			return false;
		}

		X509_STORE* CertStore = SSL_CTX_get_cert_store(InSslCtx);
		if (!CertStore)
		{
			X509_free(CaCert);
			OutReason = TEXT("SSL context certificate store is not available");
			return false;
		}

		if (X509_STORE_add_cert(CertStore, CaCert) != 1)
		{
			X509_free(CaCert);
			OutReason = FString::Printf(TEXT("X509_STORE_add_cert failed: %s"), *GetOpenSslQueueErrorString());
			return false;
		}

		X509_free(CaCert);
		return true;
	}
#endif

#if PLATFORM_WINDOWS
	bool LoadWindowsRootCertificatesIntoSslContext(SSL_CTX* InSslCtx)
	{
		if (!InSslCtx)
		{
			return false;
		}

		X509_STORE* CertStore = SSL_CTX_get_cert_store(InSslCtx);
		if (!CertStore)
		{
			OD_LOG(Warning, TEXT("OpenSSL: SSL context certificate store is unavailable on Windows"));
			return false;
		}

		HCERTSTORE WindowsRootStore = CertOpenSystemStoreW(static_cast<HCRYPTPROV_LEGACY>(0), L"ROOT");
		if (!WindowsRootStore)
		{
			OD_LOG(Warning, TEXT("OpenSSL: failed to open Windows ROOT certificate store"));
			return false;
		}

		int32 AddedCount = 0;
		int32 DuplicateCount = 0;
		int32 ParseFailureCount = 0;
		int32 AddFailureCount = 0;

		PCCERT_CONTEXT CertContext = nullptr;
		while ((CertContext = CertEnumCertificatesInStore(WindowsRootStore, CertContext)) != nullptr)
		{
			const unsigned char* EncodedPtr = CertContext->pbCertEncoded;
			X509* ParsedCert = d2i_X509(nullptr, &EncodedPtr, static_cast<long>(CertContext->cbCertEncoded));
			if (!ParsedCert)
			{
				++ParseFailureCount;
				ERR_clear_error();
				continue;
			}

			if (X509_STORE_add_cert(CertStore, ParsedCert) == 1)
			{
				++AddedCount;
			}
			else
			{
				const unsigned long ErrCode = ERR_peek_last_error();
				bool bAlreadyExists = false;
#ifdef X509_R_CERT_ALREADY_IN_HASH_TABLE
				bAlreadyExists = (ERR_GET_REASON(ErrCode) == X509_R_CERT_ALREADY_IN_HASH_TABLE);
#endif
				if (bAlreadyExists)
				{
					++DuplicateCount;
					ERR_clear_error();
				}
				else
				{
					++AddFailureCount;
					ERR_clear_error();
				}
			}

			X509_free(ParsedCert);
		}

		CertCloseStore(WindowsRootStore, 0);
		OD_LOG(Display,
			TEXT("OpenSSL: loaded Windows ROOT store certificates (added=%d, duplicates=%d, parseFailed=%d, addFailed=%d)"),
			AddedCount,
			DuplicateCount,
			ParseFailureCount,
			AddFailureCount);
		return AddedCount > 0 || DuplicateCount > 0;
	}
#endif
}

// Custom BIO methods for wrapping FSocket operations

// Helper function to wait for socket readiness using select()
// Returns true if socket is ready, false on timeout or error
static bool WaitForSocketReady(FSocket* Socket, bool bWaitForRead, bool bWaitForWrite, float TimeoutSeconds)
{
	if (!Socket)
	{
		return false;
	}

	// Use FSocket::Wait() which internally uses select/poll
	const FTimespan Timeout = FTimespan::FromSeconds(TimeoutSeconds);
	
	if (bWaitForRead && bWaitForWrite)
	{
		// Try read first, then write
		return Socket->Wait(ESocketWaitConditions::WaitForReadOrWrite, Timeout);
	}
	else if (bWaitForRead)
	{
		return Socket->Wait(ESocketWaitConditions::WaitForRead, Timeout);
	}
	else if (bWaitForWrite)
	{
		return Socket->Wait(ESocketWaitConditions::WaitForWrite, Timeout);
	}
	
	return false;
}

static bool IsRetryableSocketError(const ESocketErrors Error)
{
	return Error == SE_EWOULDBLOCK ||
		Error == SE_EINPROGRESS ||
		Error == SE_EALREADY;
}

static bool ShouldTreatReadableSocketAsDisconnected(FSocket* Socket, int32& ConsecutiveReadableNoDataCount)
{
	if (!Socket)
	{
		return true;
	}

	if (!Socket->Wait(ESocketWaitConditions::WaitForRead, FTimespan::FromMilliseconds(0)))
	{
		ConsecutiveReadableNoDataCount = 0;
		return false;
	}

	int32 PeekBytesRead = 0;
	uint8 Dummy = 0;
	const bool bPeekResult = Socket->Recv(&Dummy, 1, PeekBytesRead, ESocketReceiveFlags::Peek);
	auto* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
	const ESocketErrors LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;
	const ESocketConnectionState ConnectionState = Socket->GetConnectionState();

	if (bPeekResult && PeekBytesRead > 0)
	{
		ConsecutiveReadableNoDataCount = 0;
		return false;
	}

	if (ConnectionState == SCS_Connected && IsRetryableSocketError(LastSocketError))
	{
		ConsecutiveReadableNoDataCount = 0;
		return false;
	}

	const bool bConnectedWithNoSocketError =
		ConnectionState == SCS_Connected && LastSocketError == SE_NO_ERROR;

#if PLATFORM_ANDROID || PLATFORM_IOS
	constexpr int32 DisconnectThreshold = 20;
#else
	constexpr int32 DisconnectThreshold = 3;
#endif

	if (bConnectedWithNoSocketError)
	{
		ConsecutiveReadableNoDataCount++;
		return ConsecutiveReadableNoDataCount >= DisconnectThreshold;
	}

	ConsecutiveReadableNoDataCount = 0;
	return true;
}

static FString GetErrnoMessage(int ErrorCode)
{
	if (ErrorCode == 0)
	{
		return TEXT("Undefined error: 0");
	}

#if PLATFORM_WINDOWS
	char Buffer[256];
	const errno_t Result = strerror_s(Buffer, sizeof(Buffer), ErrorCode);
	if (Result != 0)
	{
		return FString::Printf(TEXT("Unknown error: %d"), ErrorCode);
	}
	return UTF8_TO_TCHAR(Buffer);
#else
	char Buffer[256];
#if PLATFORM_MAC
	if (strerror_r(ErrorCode, Buffer, sizeof(Buffer)) != 0)
	{
		return FString::Printf(TEXT("Unknown error: %d"), ErrorCode);
	}
	return UTF8_TO_TCHAR(Buffer);
#else
	// On glibc with _GNU_SOURCE, strerror_r returns char*. Otherwise it returns int.
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
	char* Result = strerror_r(ErrorCode, Buffer, sizeof(Buffer));
	return UTF8_TO_TCHAR(Result ? Result : "Unknown error");
#else
	if (strerror_r(ErrorCode, Buffer, sizeof(Buffer)) != 0)
	{
		return FString::Printf(TEXT("Unknown error: %d"), ErrorCode);
	}
	return UTF8_TO_TCHAR(Buffer);
#endif
#endif
#endif
}

static bool IsExpectedTlsHandshakeFailureForOpenSslConnection(const FString& ErrorMessage)
{
	return ErrorMessage.Contains(TEXT("SSL_ERROR_SYSCALL")) ||
		ErrorMessage.Contains(TEXT("SSL_ERROR_ZERO_RETURN")) ||
		ErrorMessage.Contains(TEXT("socket disconnected while waiting for handshake")) ||
		ErrorMessage.Contains(TEXT("timeout while waiting for handshake")) ||
		ErrorMessage.Contains(TEXT("wrong version number")) ||
		ErrorMessage.Contains(TEXT("ssl3_get_record")) ||
		ErrorMessage.Contains(TEXT("tlsv1 alert protocol version")) ||
		ErrorMessage.Contains(TEXT("Certificate verification failed")) ||
		ErrorMessage.Contains(TEXT("peer did not return a certificate")) ||
		ErrorMessage.Contains(TEXT("certificate required")) ||
		ErrorMessage.Contains(TEXT("certificate verify failed")) ||
		ErrorMessage.Contains(TEXT("invalid padding")) ||
		ErrorMessage.Contains(TEXT("block type is not 01")) ||
		ErrorMessage.Contains(TEXT("padding check failed")) ||
		ErrorMessage.Contains(TEXT("data too large for modulus")) ||
		ErrorMessage.Contains(TEXT("unknown ca")) ||
		ErrorMessage.Contains(TEXT("Server identity verification failed")) ||
		ErrorMessage.Contains(TEXT("Self-signed certificates require public key pinning")) ||
		ErrorMessage.Contains(TEXT("Public key pinning failed")) ||
		ErrorMessage.Contains(TEXT("No peer certificate available for pinning verification")) ||
		ErrorMessage.Contains(TEXT("Failed to extract public key from peer certificate")) ||
		ErrorMessage.Contains(TEXT("Failed to serialize public key"));
}

static FString GetOpenSslEnvironmentVariableCompat(const TCHAR* Name)
{
#if PLATFORM_ANDROID || PLATFORM_IOS
	const FTCHARToUTF8 NameUtf8(Name);
	const char* Value = ::getenv(NameUtf8.Get());
	return Value ? UTF8_TO_TCHAR(Value) : FString();
#else
	return FPlatformMisc::GetEnvironmentVariable(Name);
#endif
}

static double GetDefaultTlsHandshakeTimeoutSeconds()
{
#if PLATFORM_IOS || PLATFORM_ANDROID
	// Mobile devices and USB-connected runners can need more time for concurrent handshakes.
	return 15.0;
#else
	return 8.0;
#endif
}

static double GetTlsHandshakeTimeoutSeconds()
{
	// Avoid function-local static initialization here because iOS can abort on recursive init.
	constexpr double MinTimeoutSeconds = 1.0;
	constexpr double MaxTimeoutSeconds = 120.0;
	const double DefaultTimeoutSeconds = GetDefaultTlsHandshakeTimeoutSeconds();
	const FString TimeoutText = GetOpenSslEnvironmentVariableCompat(TEXT("OBJECTDELIVERER_TLS_HANDSHAKE_TIMEOUT_SEC"));
	if (TimeoutText.IsEmpty())
	{
		return DefaultTimeoutSeconds;
	}

	const double ParsedTimeoutSeconds = FCString::Atod(*TimeoutText);
	if (ParsedTimeoutSeconds >= MinTimeoutSeconds && ParsedTimeoutSeconds <= MaxTimeoutSeconds)
	{
		OD_LOG(Log, TEXT("Using TLS handshake timeout override: %.2f seconds"), ParsedTimeoutSeconds);
		return ParsedTimeoutSeconds;
	}

	OD_LOG(Warning, TEXT("Ignoring invalid OBJECTDELIVERER_TLS_HANDSHAKE_TIMEOUT_SEC='%s'; using default %.2f seconds"),
		*TimeoutText,
		DefaultTimeoutSeconds);
	return DefaultTimeoutSeconds;
}

static bool IsNumericIpIdentity(const FString& Identity)
{
	if (Identity.IsEmpty())
	{
		return false;
	}

	const FTCHARToUTF8 IdentityUtf8(*Identity);
	const char* IdentityAnsi = IdentityUtf8.Get();

	unsigned char Buffer[sizeof(struct in6_addr)];
	if (inet_pton(AF_INET, IdentityAnsi, Buffer) == 1)
	{
		return true;
	}

	return inet_pton(AF_INET6, IdentityAnsi, Buffer) == 1;
}

static bool VerifyPeerIdentity(SSL* InSsl, const FString& Identity, FString& OutLastError)
{
	if (!InSsl || Identity.IsEmpty())
	{
		return true;
	}

	X509* PeerCert = SSL_get_peer_certificate(InSsl);
	if (!PeerCert)
	{
		OutLastError = TEXT("Server identity verification failed: peer certificate is not available");
		return false;
	}

	const FTCHARToUTF8 IdentityUtf8(*Identity);
	const bool bIsIpIdentity = IsNumericIpIdentity(Identity);
	int VerificationResult = 0;

	if (bIsIpIdentity)
	{
		VerificationResult = X509_check_ip_asc(PeerCert, IdentityUtf8.Get(), 0);
	}
	else
	{
		VerificationResult = X509_check_host(PeerCert, IdentityUtf8.Get(), 0, 0, nullptr);
	}

	X509_free(PeerCert);

	if (VerificationResult == 1)
	{
		return true;
	}

	OutLastError = FString::Printf(
		TEXT("Server identity verification failed: certificate does not match %s '%s'"),
		bIsIpIdentity ? TEXT("IP") : TEXT("hostname"),
		*Identity);
	return false;
}

static bool IsPeerCertificateSelfSigned(SSL* InSsl, bool& bOutIsSelfSigned, FString& OutLastError)
{
	bOutIsSelfSigned = false;

	if (!InSsl)
	{
		OutLastError = TEXT("Self-signed detection failed: SSL handle is null");
		return false;
	}

	X509* PeerCert = SSL_get_peer_certificate(InSsl);
	if (!PeerCert)
	{
		OutLastError = TEXT("Self-signed detection failed: peer certificate is not available");
		return false;
	}

	// X509_check_issued(cert, cert) == X509_V_OK indicates a self-issued cert.
	// Combine with signature verification using the same cert public key for self-signed detection.
	const int SelfIssuedResult = X509_check_issued(PeerCert, PeerCert);
	EVP_PKEY* PubKey = X509_get_pubkey(PeerCert);
	if (!PubKey)
	{
		X509_free(PeerCert);
		OutLastError = TEXT("Self-signed detection failed: could not extract peer public key");
		return false;
	}

	const int SignatureVerifyResult = X509_verify(PeerCert, PubKey);
	EVP_PKEY_free(PubKey);
	X509_free(PeerCert);

	bOutIsSelfSigned = (SelfIssuedResult == X509_V_OK) && (SignatureVerifyResult == 1);
	return true;
}

// Forward declarations for BIO callback functions
static int SocketBioWrite(BIO* Bio, const char* Data, int Size);
static int SocketBioRead(BIO* Bio, char* Data, int Size);
static long SocketBioCtrl(BIO* Bio, int Cmd, long Num, void* Ptr);
static int SocketBioCreate(BIO* Bio);
static int SocketBioDestroy(BIO* Bio);

// Singleton to manage BIO_METHOD lifecycle
class FSocketBioMethodManager
{
public:
	FSocketBioMethodManager() : Method(nullptr) {}
	static FSocketBioMethodManager& Get();

	BIO_METHOD* GetMethod()
	{
		FScopeLock MethodLock(&MethodMutex);

		if (Method)
		{
			return Method;
		}

		int TypeId = BIO_get_new_index() | BIO_TYPE_SOURCE_SINK;
		Method = BIO_meth_new(TypeId, "FSocket BIO");
		if (Method)
		{
			BIO_meth_set_write(Method, SocketBioWrite);
			BIO_meth_set_read(Method, SocketBioRead);
			BIO_meth_set_ctrl(Method, SocketBioCtrl);
			BIO_meth_set_create(Method, SocketBioCreate);
			BIO_meth_set_destroy(Method, SocketBioDestroy);
		}

		return Method;
	}

	void Cleanup()
	{
		FScopeLock MethodLock(&MethodMutex);

		if (Method)
		{
			BIO_meth_free(Method);
			Method = nullptr;
		}
	}

	~FSocketBioMethodManager()
	{
		Cleanup();
	}

private:
	FSocketBioMethodManager(const FSocketBioMethodManager&) = delete;
	FSocketBioMethodManager& operator=(const FSocketBioMethodManager&) = delete;

	FCriticalSection MethodMutex;
	BIO_METHOD* Method;
};

// iOS may abort on recursive initialization of function-local statics.
// Keep these initializers at namespace scope and guard runtime initialization with explicit locks.
static FSocketBioMethodManager GSocketBioMethodManager;
static FCriticalSection GOpenSslInitMutex;
static bool GOpenSslInitialized = false;

FSocketBioMethodManager& FSocketBioMethodManager::Get()
{
	return GSocketBioMethodManager;
}

static bool EnsureOpenSslInitialized(FString& OutLastError)
{
	FScopeLock InitLock(&GOpenSslInitMutex);
	if (GOpenSslInitialized)
	{
		return true;
	}

	if (OPENSSL_init_ssl(0, nullptr) != 1)
	{
		OutLastError = TEXT("Failed to initialize OpenSSL");
		return false;
	}

	GOpenSslInitialized = true;
	return true;
}

static int SocketBioWrite(BIO* Bio, const char* Data, int Size)
{
	if (!Bio || !Data)
	{
		return -1;
	}

	if (Size == 0)
	{
		return 0;
	}

	if (Size < 0)
	{
		return -1;
	}

	FSocket* Socket = static_cast<FSocket*>(BIO_get_data(Bio));
	if (!Socket)
	{
		return -1;
	}

	BIO_clear_retry_flags(Bio);
	int32 BytesSent = 0;
	bool bSendResult = Socket->Send(reinterpret_cast<const uint8*>(Data), Size, BytesSent);

	if (bSendResult && BytesSent > 0)
	{
		return BytesSent;
	}

	auto* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
	const ESocketErrors LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;
	const bool bNoError = (LastSocketError == SE_NO_ERROR);

	const bool bRetryable =
		LastSocketError == SE_EWOULDBLOCK ||
		LastSocketError == SE_EINPROGRESS ||
		LastSocketError == SE_EALREADY;

	if (LastSocketError == SE_EPIPE)
	{
		errno = EPIPE;
		return -1;
	}

#if PLATFORM_MAC || PLATFORM_UNIX
	if (static_cast<int>(LastSocketError) == MACOS_EPIPE_ERROR_CODE)
	{
		errno = EPIPE;
		return -1;
	}
#endif

	const ESocketConnectionState ConnState = Socket->GetConnectionState();
	if (bRetryable || (bSendResult && BytesSent == 0 && ConnState == SCS_Connected) || (bNoError && ConnState == SCS_Connected))
	{
		BIO_set_retry_write(Bio);
		return -1;
	}

	if (!bRetryable && !bNoError)
	{
		errno = ECONNRESET;
	}
	return -1;
}

static int SocketBioRead(BIO* Bio, char* Data, int Size)
{
	if (!Bio || !Data)
	{
		return -1;
	}

	if (Size == 0)
	{
		return 0;
	}

	if (Size < 0)
	{
		return -1;
	}

	FSocket* Socket = static_cast<FSocket*>(BIO_get_data(Bio));
	if (!Socket)
	{
		return -1;
	}

	BIO_clear_retry_flags(Bio);
	int32 BytesRead = 0;
	bool bRecvResult = Socket->Recv(reinterpret_cast<uint8*>(Data), Size, BytesRead, ESocketReceiveFlags::None);

	if (bRecvResult && BytesRead > 0)
	{
		return BytesRead;
	}

	auto* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
	const ESocketErrors LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;
	const bool bNoError = (LastSocketError == SE_NO_ERROR);

	const bool bRetryable =
		LastSocketError == SE_EWOULDBLOCK ||
		LastSocketError == SE_EINPROGRESS ||
		LastSocketError == SE_EALREADY;

	if (LastSocketError == SE_EPIPE)
	{
		errno = EPIPE;
		return -1;
	}

#if PLATFORM_MAC || PLATFORM_UNIX
	if (static_cast<int>(LastSocketError) == MACOS_EPIPE_ERROR_CODE)
	{
		errno = EPIPE;
		return -1;
	}
#endif

	const ESocketConnectionState ConnState = Socket->GetConnectionState();
	if (bRecvResult && BytesRead == 0 && ConnState != SCS_Connected)
	{
		return 0;
	}

	if (bRetryable || (bRecvResult && BytesRead == 0 && ConnState == SCS_Connected) || (bNoError && ConnState == SCS_Connected))
	{
		BIO_set_retry_read(Bio);
		return -1;
	}

	if (!bRetryable && !bNoError)
	{
		errno = ECONNRESET;
	}
	return -1;
}

static long SocketBioCtrl(BIO* Bio, int Cmd, long Num, void* Ptr)
{
	switch (Cmd)
	{
	case BIO_CTRL_FLUSH:
		return 1;
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
		return 0;
	default:
		return 0;
	}
}

static int SocketBioCreate(BIO* Bio)
{
	BIO_set_init(Bio, 1);
	BIO_set_data(Bio, nullptr);
	BIO_set_shutdown(Bio, 0);
	return 1;
}

static int SocketBioDestroy(BIO* Bio)
{
	if (!Bio)
	{
		return 0;
	}

	BIO_set_data(Bio, nullptr);
	BIO_set_init(Bio, 0);
	return 1;
}

static BIO_METHOD* GetSocketBioMethod()
{
	return FSocketBioMethodManager::Get().GetMethod();
}

static FString CollectOpenSslErrors()
{
	FString CombinedErrors;
	unsigned long ErrCode = 0;
	while ((ErrCode = ERR_get_error()) != 0)
	{
		char ErrMsg[256];
		ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
		if (!CombinedErrors.IsEmpty())
		{
			CombinedErrors += TEXT(" | ");
		}
		CombinedErrors += UTF8_TO_TCHAR(ErrMsg);
	}
	return CombinedErrors;
}

static void TryShutdownSsl(SSL* Ssl)
{
	if (!Ssl)
	{
		return;
	}

	SSL_shutdown(Ssl);
}

static int GetTlsMinimumVersionValue(EObjectDelivererTlsProtocol MinimumProtocol)
{
	switch (MinimumProtocol)
	{
	case EObjectDelivererTlsProtocol::TLSv1_2:
		return TLS1_2_VERSION;
	case EObjectDelivererTlsProtocol::TLSv1_1:
		return TLS1_1_VERSION;
	case EObjectDelivererTlsProtocol::TLSv1_0:
		return TLS1_VERSION;
	default:
		return TLS1_2_VERSION;
	}
}

static int GetOpenSslVerifyMode(EObjectDelivererTlsClientAuthMode Mode)
{
	switch (Mode)
	{
	case EObjectDelivererTlsClientAuthMode::Optional:
		return SSL_VERIFY_PEER;
	case EObjectDelivererTlsClientAuthMode::Required:
		return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	case EObjectDelivererTlsClientAuthMode::None:
	default:
		return SSL_VERIFY_NONE;
	}
}

static SSL_CTX* CreateNativeSslContext(EObjectDelivererTlsProtocol MinimumProtocol)
{
	const SSL_METHOD* Method = TLS_method();
	if (!Method)
	{
		return nullptr;
	}

	SSL_CTX* NativeCtx = SSL_CTX_new(Method);
	if (!NativeCtx)
	{
		return nullptr;
	}

	const int VersionValue = GetTlsMinimumVersionValue(MinimumProtocol);
	SSL_CTX_set_min_proto_version(NativeCtx, VersionValue);

	SSL_CTX_set_options(NativeCtx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_ecdh_auto(NativeCtx, 1);
	SSL_CTX_set_options(NativeCtx, SSL_OP_SINGLE_ECDH_USE);

	// Prefer common ECDHE/TLS1.2 ciphers and allow TLS1.3 defaults
	SSL_CTX_set_cipher_list(NativeCtx, "DEFAULT");
	SSL_CTX_set_ciphersuites(NativeCtx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");

	// Load platform default trust store (may be no-op depending on platform packaging).
	// Failure is not fatal here; verification logic will surface issues via SSL_get_verify_result().
	SSL_CTX_set_default_verify_paths(NativeCtx);

	// Share UE's bundled/project CA bundle with ObjectDeliverer's OpenSSL context.
	FSslModule::Get().GetCertificateManager().AddCertificatesToSslContext(NativeCtx);

#if PLATFORM_WINDOWS
	// Unreal's OpenSSL on Windows does not always resolve OS trust roots via default verify paths.
	// Import Windows ROOT certificates explicitly so public CAs (e.g. Let's Encrypt) can be verified.
	LoadWindowsRootCertificatesIntoSslContext(NativeCtx);
#endif

	return NativeCtx;
}

static int AllowAllCertificatesVerifyCallback(int /*PreverifyOk*/, X509_STORE_CTX* /*StoreCtx*/)
{
	// Always return success to allow TLS handshake completion.
	// The caller checks SSL_get_verify_result() after SSL_connect() to enforce policy.
	return 1;
}

// SSL Worker Thread - handles all SSL operations on a dedicated thread
class FSSLWorkerThread : public FRunnable
{
public:
	FSSLWorkerThread(FOpenSslConnection* InConnection)
		: Connection(InConnection)
		, StopTaskCounter(0)
	{
	}

	virtual ~FSSLWorkerThread()
	{
	}

	virtual bool Init() override
	{
		return true;
	}

	virtual uint32 Run() override
	{
		int32 LoopCount = 0;
		int32 ConsecutiveReadableNoDataCount = 0;
		while (!Connection->bStopWorker.load())
		{
			LoopCount++;

			// Check for data to send
			{
				FScopeLock Lock(&Connection->SendQueueMutex);
				TArray<uint8> DataToSend;
				while (Connection->SendQueue.Dequeue(DataToSend))
				{
					if (Connection->Ssl && Connection->bConnected)
					{
						int32 TotalSent = 0;
						int32 Size = DataToSend.Num();
						while (TotalSent < Size)
						{
							int32 BytesSent = SSL_write(Connection->Ssl, DataToSend.GetData() + TotalSent, Size - TotalSent);
							if (BytesSent <= 0)
							{
								int Error = SSL_get_error(Connection->Ssl, BytesSent);
								if (Error == SSL_ERROR_WANT_WRITE || Error == SSL_ERROR_WANT_READ)
								{
									FPlatformProcess::Sleep(0.001f);
									continue;
								}
								break;
							}
							TotalSent += BytesSent;
						}
					}
				}
			}

			// Check for data to receive
			// Always try SSL_read() to ensure we don't miss any data
			// The "wrong version number" error will be handled gracefully
			if (Connection->Ssl && Connection->bConnected)
			{
				uint8 TempBuffer[4096];
				int32 BytesReceived = SSL_read(Connection->Ssl, TempBuffer, sizeof(TempBuffer));
				if (BytesReceived > 0)
				{
					ConsecutiveReadableNoDataCount = 0;
					// Notify received data via callback
					Connection->DataReceivedDelegate.Broadcast(TempBuffer, BytesReceived);
				}
				else
				{
					int Error = SSL_get_error(Connection->Ssl, BytesReceived);
						if (Error == SSL_ERROR_WANT_READ || Error == SSL_ERROR_WANT_WRITE)
						{
							if (ShouldTreatReadableSocketAsDisconnected(Connection->Socket, ConsecutiveReadableNoDataCount) && LoopCount > 100)
							{
								OD_LOG(Warning, TEXT("SSL Worker: socket became readable with no TLS payload, marking as disconnected"));
								Connection->bConnected = false;
								Connection->NotifyDisconnected();
								break;
							}

							// Some platforms may keep returning WANT_* after the peer has already closed.
							const ESocketConnectionState ConnState = Connection->Socket ? Connection->Socket->GetConnectionState() : SCS_ConnectionError;
							if (ConnState != SCS_Connected && LoopCount > 100)
							{
								OD_LOG(Warning, TEXT("SSL Worker: SSL_read returned %s while socket is not connected (connState=%d), marking as disconnected"),
									Error == SSL_ERROR_WANT_READ ? TEXT("SSL_ERROR_WANT_READ") : TEXT("SSL_ERROR_WANT_WRITE"),
									static_cast<int32>(ConnState));
								Connection->bConnected = false;
								Connection->NotifyDisconnected();
								break;
							}
						}
					else if (Error == SSL_ERROR_ZERO_RETURN)
					{
						// Connection closed - only after startup grace period
						if (LoopCount > 100)
						{
							OD_LOG(Warning, TEXT("SSL Worker: Connection closed (SSL_ERROR_ZERO_RETURN)"));
							Connection->bConnected = false;
							Connection->NotifyDisconnected();
							break;
						}
					}
					else if (Error == SSL_ERROR_SYSCALL)
					{
						// On some platforms (notably Windows), SSL_ERROR_SYSCALL with errno=0
						// can indicate EOF/connection close rather than "no data yet".
						const ESocketConnectionState ConnState = Connection->Socket ? Connection->Socket->GetConnectionState() : SCS_ConnectionError;
						const bool bLikelyDisconnected = (errno != 0) || (BytesReceived == 0) || (ConnState != SCS_Connected);
						if (bLikelyDisconnected)
						{
							if (LoopCount > 100)
							{
								OD_LOG(Warning, TEXT("SSL Worker: SSL_ERROR_SYSCALL (errno=%d, bytes=%d, connState=%d), marking as disconnected"),
									errno,
									BytesReceived,
									static_cast<int32>(ConnState));
								Connection->bConnected = false;
								Connection->NotifyDisconnected();
								break;
							}
						}
						else if (ShouldTreatReadableSocketAsDisconnected(Connection->Socket, ConsecutiveReadableNoDataCount) && LoopCount > 100)
						{
							OD_LOG(Warning, TEXT("SSL Worker: raw socket probe detected disconnect after SSL_ERROR_SYSCALL"));
							Connection->bConnected = false;
							Connection->NotifyDisconnected();
							break;
						}
					}
						else if (Error == SSL_ERROR_SSL)
						{
							// SSL protocol error - check if it's a temporary "wrong version number" error
							unsigned long ErrCode = ERR_get_error();
							if (ErrCode != 0)
							{
								unsigned long Reason = ERR_GET_REASON(ErrCode);
								if (Reason == SSL_R_WRONG_VERSION_NUMBER || Reason == SSL_R_TLSV1_ALERT_PROTOCOL_VERSION)
								{
									// These errors can occur transiently right after startup on some platforms.
									// If they persist beyond the startup grace period, treat as disconnected.
									if (LoopCount > 100)
									{
										char ErrMsg[256];
										ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
										OD_LOG(Warning, TEXT("SSL Worker: persistent TLS protocol error %d (%s), marking as disconnected"), Error, UTF8_TO_TCHAR(ErrMsg));
										Connection->bConnected = false;
										Connection->NotifyDisconnected();
										break;
									}
								}
								else
								{
									// Other SSL errors - log and mark as disconnected
									if (LoopCount > 100)
									{
										char ErrMsg[256];
										ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
										OD_LOG(Warning, TEXT("SSL Worker: SSL_read error %d (%s), marking as disconnected"), Error, UTF8_TO_TCHAR(ErrMsg));
										Connection->bConnected = false;
										Connection->NotifyDisconnected();
										break;
									}
								}
							}
							else if (LoopCount > 100)
							{
								// Some handshake failures surface as SSL_ERROR_SSL with an empty error queue.
								// Treat this as a disconnect to avoid leaving connection state stale.
								const ESocketConnectionState ConnState = Connection->Socket ? Connection->Socket->GetConnectionState() : SCS_ConnectionError;
								OD_LOG(Warning, TEXT("SSL Worker: SSL_ERROR_SSL with empty OpenSSL error queue (bytes=%d, connState=%d), marking as disconnected"),
									BytesReceived,
									static_cast<int32>(ConnState));
								Connection->bConnected = false;
								Connection->NotifyDisconnected();
								break;
							}
						}

					if (Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
					{
						ConsecutiveReadableNoDataCount = 0;
					}
				}
			}

			// Small sleep to prevent busy-waiting
			FPlatformProcess::Sleep(0.001f);  // 1ms
		}

		return 0;
	}

	virtual void Stop() override
	{
		Connection->bStopWorker.store(true);
	}

private:
	FOpenSslConnection* Connection;
	std::atomic<uint32> StopTaskCounter;
};

FOpenSslConnection::FOpenSslConnection()
{
}

FOpenSslConnection::~FOpenSslConnection()
{
	Close();
}

bool FOpenSslConnection::InitializeForClient(EObjectDelivererTlsProtocol MinimumProtocol)
{
	if (!CreateSslContext(MinimumProtocol))
	{
		return false;
	}

	bIsServer = false;
	return true;
}

bool FOpenSslConnection::InitializeForServer(const FString& CertPath, const FString& KeyPath, EObjectDelivererTlsProtocol MinimumProtocol)
{
	bIsServer = true;

	if (!CreateSslContext(MinimumProtocol))
	{
		return false;
	}

	if (!LoadCertificateAndKey(CertPath, KeyPath))
	{
		return false;
	}

	if (!ApplyServerClientAuthSettings())
	{
		return false;
	}

	SSL_CTX_set_mode(SslCtx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_ecdh_auto(SslCtx, 1);
	SSL_CTX_set_options(SslCtx, SSL_OP_SINGLE_ECDH_USE);
	SSL_CTX_set_cipher_list(SslCtx, "DEFAULT");
	SSL_CTX_set_ciphersuites(SslCtx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");

	return true;
}

bool FOpenSslConnection::Connect(FSocket* InSocket, const FString& HostName)
{
	Socket = InSocket;

	Ssl = SSL_new(SslCtx);
	if (!Ssl)
	{
		LastError = TEXT("Failed to create SSL structure");
		return false;
	}

	if (!SetupSocketBio(InSocket))
	{
		SSL_free(Ssl);
		Ssl = nullptr;
		return false;
	}

	const bool bIsNumericIpHostName = IsNumericIpIdentity(HostName);
	if (!HostName.IsEmpty() && !bIsNumericIpHostName)
	{
		SSL_set_tlsext_host_name(Ssl, TCHAR_TO_UTF8(*HostName));
	}

	// Allow handshake completion even with certificate issues, then enforce policy after SSL_connect().
	if (bVerifyPeer)
	{
		SSL_set_verify(Ssl, SSL_VERIFY_PEER, AllowAllCertificatesVerifyCallback);
	}
	else
	{
		SSL_set_verify(Ssl, SSL_VERIFY_NONE, nullptr);
	}

	const double TimeoutSeconds = GetTlsHandshakeTimeoutSeconds();
	OD_LOG(Warning, TEXT("SSL_connect: Starting TLS handshake on client side (timeout=%.2fs)"), TimeoutSeconds);
	const double StartTime = FPlatformTime::Seconds();
	double NextProgressLogTime = StartTime + 1.0;
	int RetryCount = 0;
	while (true)
	{
		int Result = SSL_connect(Ssl);
		if (Result == 1)
		{
			// Enable AUTO_RETRY mode on the SSL object to handle SSL_ERROR_WANT_READ/WRITE automatically
			SSL_set_mode(Ssl, SSL_MODE_AUTO_RETRY);
			break;
		}

		int Error = SSL_get_error(Ssl, Result);
		if (Error == SSL_ERROR_WANT_READ || Error == SSL_ERROR_WANT_WRITE)
		{
			RetryCount++;
			const ESocketConnectionState ConnState = Socket ? Socket->GetConnectionState() : SCS_ConnectionError;
			if (ConnState != SCS_Connected)
			{
				LastError = FString::Printf(TEXT("socket disconnected while waiting for handshake (connState=%d)"), static_cast<int32>(ConnState));
				break;
			}

			const double ElapsedTime = FPlatformTime::Seconds() - StartTime;
			if (FPlatformTime::Seconds() >= NextProgressLogTime)
			{
				OD_LOG(Warning, TEXT("SSL_connect: Still waiting for handshake (elapsed=%.2fs, retries=%d, error=%s)"),
					ElapsedTime,
					RetryCount,
					Error == SSL_ERROR_WANT_READ ? TEXT("WANT_READ") : TEXT("WANT_WRITE"));
				NextProgressLogTime += 1.0;
			}
			if (ElapsedTime > TimeoutSeconds)
			{
				LastError = TEXT("timeout while waiting for handshake");
				OD_LOG(Warning, TEXT("SSL_connect: Timeout after %.2f seconds and %d retries"), ElapsedTime, RetryCount);
				break;
			}

			// Use select() to wait for socket readiness instead of busy-waiting
			// This allows the OS to properly schedule I/O and prevents deadlocks on Windows
			const bool bWaitForRead = (Error == SSL_ERROR_WANT_READ);
			const bool bWaitForWrite = (Error == SSL_ERROR_WANT_WRITE);
			const float WaitTimeout = 0.01f;  // 10ms wait per iteration
			
			const bool bSocketReady = WaitForSocketReady(Socket, bWaitForRead, bWaitForWrite, WaitTimeout);
			if (!bSocketReady)
			{
				const ESocketConnectionState WaitConnState = Socket ? Socket->GetConnectionState() : SCS_ConnectionError;
				if (WaitConnState != SCS_Connected)
				{
					LastError = FString::Printf(TEXT("socket disconnected while waiting for handshake (connState=%d)"), static_cast<int32>(WaitConnState));
					break;
				}
				// Timeout on wait is OK, just check overall timeout and retry
				// Also yield to allow other threads to run
				FPlatformProcess::Sleep(0.001f);
			}
			else
			{
				// Even when the socket reports ready, SSL may continue returning WANT_*.
				// Add a tiny yield to avoid tight spin loops on Windows.
				FPlatformProcess::Sleep(0.001f);
			}
			continue;
		}

		switch (Error)
		{
		case SSL_ERROR_ZERO_RETURN:
			LastError = TEXT("SSL_connect failed: SSL_ERROR_ZERO_RETURN - connection closed");
			break;
		case SSL_ERROR_SYSCALL:
			LastError = FString::Printf(TEXT("SSL_connect failed: SSL_ERROR_SYSCALL - %s"), *GetErrnoMessage(errno));
			break;
		default:
			{
				unsigned long ErrCode = ERR_get_error();
				char ErrMsg[256];
				ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
				LastError = FString::Printf(TEXT("SSL_connect failed: %s"), UTF8_TO_TCHAR(ErrMsg));
			}
			break;
		}
		break;
	}

	// Restore non-blocking mode after handshake
	InSocket->SetNonBlocking(true);

	if (!LastError.IsEmpty())
	{
		const auto StackErrors = CollectOpenSslErrors();
		const int SysErr = errno;
		const bool bExpectedConnectFailure = IsExpectedTlsHandshakeFailureForOpenSslConnection(LastError);
		if (bExpectedConnectFailure)
		{
			OD_LOG(Warning, TEXT("SSL_connect error: %s (errno=%d) OpenSSLStack=%s"),
				*LastError, SysErr, StackErrors.IsEmpty() ? TEXT("None") : *StackErrors);
		}
		else
		{
			OD_LOG(Error, TEXT("SSL_connect error: %s (errno=%d) OpenSSLStack=%s"),
				*LastError, SysErr, StackErrors.IsEmpty() ? TEXT("None") : *StackErrors);
		}
		TryShutdownSsl(Ssl);
		SSL_free(Ssl);
		Ssl = nullptr;
		return false;
	}

	if (bVerifyPeer)
	{
		long VerifyResult = SSL_get_verify_result(Ssl);
		if (VerifyResult != X509_V_OK)
		{
			if (!bAllowSelfSigned ||
				(VerifyResult != X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN &&
				 VerifyResult != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT))
			{
				LastError = FString::Printf(TEXT("Certificate verification failed: %ld"), VerifyResult);
				TryShutdownSsl(Ssl);
				SSL_free(Ssl);
				Ssl = nullptr;
				return false;
			}
		}
	}

	// Enforce pinning for self-signed peer certificates even when they are trusted via
	// process-global trust overrides (e.g. SSL_CERT_FILE), which can make VerifyResult == X509_V_OK.
	if (bVerifyPeer && bAllowSelfSigned)
	{
		bool bPeerCertIsSelfSigned = false;
		if (!IsPeerCertificateSelfSigned(Ssl, bPeerCertIsSelfSigned, LastError))
		{
			TryShutdownSsl(Ssl);
			SSL_free(Ssl);
			Ssl = nullptr;
			return false;
		}

		if (bPeerCertIsSelfSigned && PinnedPublicKeyDigest.IsEmpty())
		{
			LastError = TEXT(
				"SECURITY: Self-signed certificates require public key pinning to prevent man-in-the-middle attacks.\n\n"
				"Use WithAllowSelfSignedCertificates(true) and WithPinnedPublicKey() to set the expected public key hash.\n\n"
				"Example:\n"
				"  Client->WithAllowSelfSignedCertificates(true)->WithPinnedPublicKey(TEXT(\"aa:bb:cc:dd:...\"));\n\n"
				"To get the public key hash from your certificate:\n"
				"  Use UObjectDelivererCertificateGenerator::ExtractPublicKeyHash() or the certificate generator tool.\n\n"
				"See documentation: TLS_Security_Notes.md"
			);
			TryShutdownSsl(Ssl);
			SSL_free(Ssl);
			Ssl = nullptr;
			return false;
		}
	}

	if (!PinnedPublicKeyDigest.IsEmpty())
	{
		X509* PeerCert = SSL_get_peer_certificate(Ssl);
		if (!PeerCert)
		{
			LastError = TEXT("No peer certificate available for pinning verification");
			TryShutdownSsl(Ssl);
			SSL_free(Ssl);
			Ssl = nullptr;
			return false;
		}

		EVP_PKEY* PubKey = X509_get_pubkey(PeerCert);
		X509_free(PeerCert);

		if (!PubKey)
		{
			LastError = TEXT("Failed to extract public key from peer certificate");
			TryShutdownSsl(Ssl);
			SSL_free(Ssl);
			Ssl = nullptr;
			return false;
		}

		unsigned char* PubKeyDer = nullptr;
		int PubKeyLen = i2d_PUBKEY(PubKey, &PubKeyDer);
		EVP_PKEY_free(PubKey);

		if (PubKeyLen <= 0)
		{
			LastError = TEXT("Failed to serialize public key");
			TryShutdownSsl(Ssl);
			SSL_free(Ssl);
			Ssl = nullptr;
			return false;
		}

		uint8 Hash[SHA256_DIGEST_LENGTH];
		SHA256(PubKeyDer, PubKeyLen, Hash);
		OPENSSL_free(PubKeyDer);

		FString CalculatedHash;
		for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
		{
			CalculatedHash += FString::Printf(TEXT("%02x"), Hash[i]);
			if (i < SHA256_DIGEST_LENGTH - 1)
			{
				CalculatedHash += TEXT(":");
			}
		}

		if (CalculatedHash.ToLower() != PinnedPublicKeyDigest.ToLower())
		{
			LastError = FString::Printf(TEXT("Public key pinning failed: expected %s, got %s"), *PinnedPublicKeyDigest, *CalculatedHash);
			TryShutdownSsl(Ssl);
			SSL_free(Ssl);
			Ssl = nullptr;
			return false;
		}
	}

	if (bVerifyPeer && !HostName.IsEmpty())
	{
		if (!VerifyPeerIdentity(Ssl, HostName, LastError))
		{
			TryShutdownSsl(Ssl);
			SSL_free(Ssl);
			Ssl = nullptr;
			return false;
		}
	}

	// Note: The SSL worker thread is NOT started here to avoid race conditions.
	// The caller must:
	// 1. Register the OnDataReceived callback
	// 2. Call StartWorkerThread() to begin SSL I/O operations
	// This ensures no data is lost between Connect() returning and callback registration.

	bConnected = true;
	bDisconnectedNotified.store(false);
	return true;
}

bool FOpenSslConnection::Accept(FSocket* InSocket)
{
	Socket = InSocket;

	Ssl = SSL_new(SslCtx);
	if (!Ssl)
	{
		LastError = TEXT("Failed to create SSL structure");
		return false;
	}

	if (!SetupSocketBio(InSocket))
	{
		SSL_free(Ssl);
		Ssl = nullptr;
		return false;
	}

	const double TimeoutSeconds = GetTlsHandshakeTimeoutSeconds();
	OD_LOG(Warning, TEXT("SSL_accept: Starting TLS handshake on server side (timeout=%.2fs)"), TimeoutSeconds);
	const double StartTime = FPlatformTime::Seconds();
	double NextProgressLogTime = StartTime + 1.0;
	int RetryCount = 0;
	while (true)
	{
		int Result = SSL_accept(Ssl);
		if (Result == 1)
		{
			// Enable AUTO_RETRY mode on the SSL object to handle SSL_ERROR_WANT_READ/WRITE automatically
			SSL_set_mode(Ssl, SSL_MODE_AUTO_RETRY);
			break;
		}

		int Error = SSL_get_error(Ssl, Result);
		if (Error == SSL_ERROR_WANT_READ || Error == SSL_ERROR_WANT_WRITE)
		{
			RetryCount++;
			const ESocketConnectionState ConnState = Socket ? Socket->GetConnectionState() : SCS_ConnectionError;
			if (ConnState != SCS_Connected)
			{
				LastError = FString::Printf(TEXT("socket disconnected while waiting for handshake (connState=%d)"), static_cast<int32>(ConnState));
				break;
			}

			const double ElapsedTime = FPlatformTime::Seconds() - StartTime;
			if (FPlatformTime::Seconds() >= NextProgressLogTime)
			{
				OD_LOG(Warning, TEXT("SSL_accept: Still waiting for handshake (elapsed=%.2fs, retries=%d, error=%s)"),
					ElapsedTime,
					RetryCount,
					Error == SSL_ERROR_WANT_READ ? TEXT("WANT_READ") : TEXT("WANT_WRITE"));
				NextProgressLogTime += 1.0;
			}
			if (ElapsedTime > TimeoutSeconds)
			{
				LastError = TEXT("timeout while waiting for handshake");
				OD_LOG(Warning, TEXT("SSL_accept: Timeout after %.2f seconds and %d retries"), ElapsedTime, RetryCount);
				break;
			}

			// Use select() to wait for socket readiness instead of busy-waiting
			// This allows the OS to properly schedule I/O and prevents deadlocks on Windows
			const bool bWaitForRead = (Error == SSL_ERROR_WANT_READ);
			const bool bWaitForWrite = (Error == SSL_ERROR_WANT_WRITE);
			const float WaitTimeout = 0.01f;  // 10ms wait per iteration
			
			const bool bSocketReady = WaitForSocketReady(Socket, bWaitForRead, bWaitForWrite, WaitTimeout);
			if (!bSocketReady)
			{
				const ESocketConnectionState WaitConnState = Socket ? Socket->GetConnectionState() : SCS_ConnectionError;
				if (WaitConnState != SCS_Connected)
				{
					LastError = FString::Printf(TEXT("socket disconnected while waiting for handshake (connState=%d)"), static_cast<int32>(WaitConnState));
					break;
				}
				// Timeout on wait is OK, just check overall timeout and retry
				// Also yield to allow other threads to run
				FPlatformProcess::Sleep(0.001f);
			}
			else
			{
				// Avoid tight spin when select/poll reports readiness but SSL still wants read/write.
				FPlatformProcess::Sleep(0.001f);
			}
			continue;
		}

		switch (Error)
		{
		case SSL_ERROR_ZERO_RETURN:
			LastError = TEXT("SSL_accept failed: SSL_ERROR_ZERO_RETURN - connection closed");
			break;
		case SSL_ERROR_SYSCALL:
			LastError = FString::Printf(TEXT("SSL_accept failed: SSL_ERROR_SYSCALL - %s (errno=%d)"),
				*GetErrnoMessage(errno), errno);
			break;
		default:
			{
				unsigned long ErrCode = ERR_get_error();
				char ErrMsg[256];
				ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
				LastError = FString::Printf(TEXT("SSL_accept failed: %s"), UTF8_TO_TCHAR(ErrMsg));
			}
			break;
		}
		break;
	}

	// Restore non-blocking mode after handshake
	InSocket->SetNonBlocking(true);

	if (!LastError.IsEmpty())
	{
		const FString StackErrors = CollectOpenSslErrors();
		const int SysErr = errno;
		const auto ConnState = Socket ? static_cast<int32>(Socket->GetConnectionState()) : -1;
		// Server-side handshake failures are generally peer/input issues and should not
		// be treated as fatal server errors.
		OD_LOG(Warning, TEXT("SSL_accept error: %s (errno=%d ConnState=%d) OpenSSLStack=%s"),
			*LastError, SysErr, ConnState, StackErrors.IsEmpty() ? TEXT("None") : *StackErrors);
		if (Socket)
		{
			// Force immediate close behavior on handshake failure.
			// This helps peers (especially on Windows) observe disconnect quickly.
			Socket->SetLinger(true, 0);
		}
		TryShutdownSsl(Ssl);
		SSL_free(Ssl);
		Ssl = nullptr;
		return false;
	}

	// Note: The SSL worker thread is NOT started here to avoid race conditions.
	// The caller must:
	// 1. Register the OnDataReceived callback
	// 2. Call StartWorkerThread() to begin SSL I/O operations
	// This ensures no data is lost between Accept() returning and callback registration.

	bConnected = true;
	bDisconnectedNotified.store(false);
	return true;
}

int32 FOpenSslConnection::Send(const uint8* Data, int32 Size)
{
	if (!bConnected)
	{
		return -1;
	}

	if (WorkerThread == nullptr)
	{
		return -1;
	}

	// Queue data for the SSL worker thread to send
	{
		FScopeLock Lock(&SendQueueMutex);
		TArray<uint8> DataCopy;
		DataCopy.Append(Data, Size);
		SendQueue.Enqueue(MoveTemp(DataCopy));
	}

	return Size;  // Return immediately - actual send happens asynchronously
}

int32 FOpenSslConnection::Recv(uint8* Data, int32 Size)
{
	// Note: Recv should NOT be called directly - data is received by the worker thread
	// and delivered via callback. This is kept for compatibility but will return 0.
	if (!Ssl || !bConnected)
	{
		return -1;
	}

	int32 BytesReceived = SSL_read(Ssl, Data, Size);
	if (BytesReceived <= 0)
	{
		int Error = SSL_get_error(Ssl, BytesReceived);
		if (Error == SSL_ERROR_WANT_WRITE || Error == SSL_ERROR_WANT_READ)
		{
			return 0;
		}
		if (Error == SSL_ERROR_ZERO_RETURN)
		{
			OD_LOG(Warning, TEXT("OpenSSL Recv: SSL_ERROR_ZERO_RETURN - connection closed cleanly"));
			return -1;
		}
		if (Error == SSL_ERROR_SYSCALL)
		{
			// For non-blocking sockets, SSL_ERROR_SYSCALL with errno=0 often means
			// "no data available yet" - treat it as WANT_READ
			if (errno == 0)
			{
				return 0;
			}
			return -1;
		}
		// SSL_ERROR_SSL or other errors - check if it's a protocol version error
		unsigned long ErrCode = ERR_get_error();
		if (ErrCode != 0)
		{
			// Check for "wrong version number" error (0x1408F10B)
			if (ERR_GET_REASON(ErrCode) == SSL_R_WRONG_VERSION_NUMBER)
			{
				// This happens when SSL_read is called but no complete TLS record is available
				// Treat it as "no data yet" and continue polling
				return 0;
			}
			// Check for "tlsv1 alert protocol version" error (0x1409442E)
			if (ERR_GET_REASON(ErrCode) == SSL_R_TLSV1_ALERT_PROTOCOL_VERSION)
			{
				// Similar to above - treat as no data
				return 0;
			}
		}
		return -1;
	}

	return BytesReceived;
}

void FOpenSslConnection::Close()
{
	StopSSLWorkerThread();

	if (Ssl && bConnected)
	{
		int ShutdownResult = SSL_shutdown(Ssl);
		if (ShutdownResult < 0)
		{
			int Error = SSL_get_error(Ssl, ShutdownResult);
			if (Error != SSL_ERROR_ZERO_RETURN && Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
			{
				unsigned long ErrCode = ERR_get_error();
				char ErrMsg[256];
				ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
				OD_LOG(Warning, TEXT("SSL_shutdown failed: %s"), UTF8_TO_TCHAR(ErrMsg));
			}
		}
	}

	if (Ssl)
	{
		// SSL_free() automatically frees the BIO set via SSL_set_bio()
		SSL_free(Ssl);
		Ssl = nullptr;
		SocketBio = nullptr;
	}

	if (SslCtx)
	{
		SSL_CTX_free(SslCtx);
		SslCtx = nullptr;
	}

	bConnected = false;
	Socket = nullptr;
}

bool FOpenSslConnection::IsConnected() const
{
	return bConnected;
}

bool FOpenSslConnection::HasError() const
{
	return !LastError.IsEmpty();
}

void FOpenSslConnection::SetVerifyMode(bool bVerify, bool bInAllowSelfSigned)
{
	bVerifyPeer = bVerify;
	bAllowSelfSigned = bInAllowSelfSigned;
}

bool FOpenSslConnection::SetTrustedCaCertificate(const FString& CaCertificatePath)
{
	TrustedCaCertificatePath = CaCertificatePath;

	if (TrustedCaCertificatePath.IsEmpty())
	{
		return true;
	}

	if (!SslCtx)
	{
		return true;
	}

	FString NormalizedTrustedCaCertificatePath = NormalizeOpenSslPathForExternalRead(TrustedCaCertificatePath);

	FString FailureReason;
#if PLATFORM_ANDROID
	if (!LoadTrustedCaPemFileAndroid(SslCtx, NormalizedTrustedCaCertificatePath, FailureReason))
#else
	const FTCHARToUTF8 CaCertPathAnsi(*NormalizedTrustedCaCertificatePath);
	if (SSL_CTX_load_verify_locations(SslCtx, CaCertPathAnsi.Get(), nullptr) != 1)
#endif
	{
#if PLATFORM_ANDROID
		LastError = FString::Printf(TEXT("Failed to load CA certificate '%s' (normalized: '%s'): %s"), *TrustedCaCertificatePath, *NormalizedTrustedCaCertificatePath, *FailureReason);
#else
		unsigned long ErrCode = ERR_get_error();
		char ErrMsg[256];
		ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
		LastError = FString::Printf(TEXT("Failed to load CA certificate '%s' (normalized: '%s'): %s"), *TrustedCaCertificatePath, *NormalizedTrustedCaCertificatePath, UTF8_TO_TCHAR(ErrMsg));
#endif
		return false;
	}

	return true;
}

bool FOpenSslConnection::SetClientCertificate(const FString& CertPath, const FString& KeyPath)
{
	ClientCertificatePath = CertPath;
	ClientPrivateKeyPath = KeyPath;

	if (ClientCertificatePath.IsEmpty() || ClientPrivateKeyPath.IsEmpty())
	{
		LastError = TEXT("Client certificate path or key path is empty");
		return false;
	}

	if (!SslCtx)
	{
		return true;
	}

	const FString NormalizedClientCertificatePath = NormalizeOpenSslPathForExternalRead(ClientCertificatePath);
	const FString NormalizedClientPrivateKeyPath = NormalizeOpenSslPathForExternalRead(ClientPrivateKeyPath);

	FString ClientCertFailureReason;
#if PLATFORM_ANDROID
	if (!UseCertificatePemFileAndroid(SslCtx, NormalizedClientCertificatePath, ClientCertFailureReason))
#else
	if (SSL_CTX_use_certificate_file(SslCtx, TCHAR_TO_UTF8(*NormalizedClientCertificatePath), SSL_FILETYPE_PEM) != 1)
#endif
	{
#if PLATFORM_ANDROID
		LastError = FString::Printf(TEXT("Failed to load client certificate from '%s' (normalized: '%s'): %s"), *ClientCertificatePath, *NormalizedClientCertificatePath, *ClientCertFailureReason);
#else
		unsigned long ErrCode = ERR_get_error();
		char ErrMsg[256];
		ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
		LastError = FString::Printf(TEXT("Failed to load client certificate from '%s' (normalized: '%s'): %s"), *ClientCertificatePath, *NormalizedClientCertificatePath, UTF8_TO_TCHAR(ErrMsg));
#endif
		return false;
	}

	FString ClientKeyFailureReason;
#if PLATFORM_ANDROID
	if (!UsePrivateKeyPemFileAndroid(SslCtx, NormalizedClientPrivateKeyPath, ClientKeyFailureReason))
#else
	if (SSL_CTX_use_PrivateKey_file(SslCtx, TCHAR_TO_UTF8(*NormalizedClientPrivateKeyPath), SSL_FILETYPE_PEM) != 1)
#endif
	{
#if PLATFORM_ANDROID
		LastError = FString::Printf(TEXT("Failed to load client private key from '%s' (normalized: '%s'): %s"), *ClientPrivateKeyPath, *NormalizedClientPrivateKeyPath, *ClientKeyFailureReason);
#else
		unsigned long ErrCode = ERR_get_error();
		char ErrMsg[256];
		ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
		LastError = FString::Printf(TEXT("Failed to load client private key from '%s' (normalized: '%s'): %s"), *ClientPrivateKeyPath, *NormalizedClientPrivateKeyPath, UTF8_TO_TCHAR(ErrMsg));
#endif
		return false;
	}

	if (SSL_CTX_check_private_key(SslCtx) != 1)
	{
		LastError = TEXT("Client private key does not match client certificate");
		return false;
	}

	return true;
}

void FOpenSslConnection::SetClientAuthMode(EObjectDelivererTlsClientAuthMode Mode)
{
	ClientAuthMode = Mode;
}

bool FOpenSslConnection::SetClientCaCertificate(const FString& CaCertificatePath)
{
	ClientCaCertificatePath = CaCertificatePath;

	if (ClientCaCertificatePath.IsEmpty())
	{
		return true;
	}

	if (!SslCtx)
	{
		return true;
	}

	const FString NormalizedClientCaCertificatePath = NormalizeOpenSslPathForExternalRead(ClientCaCertificatePath);

	FString FailureReason;
#if PLATFORM_ANDROID
	if (!LoadTrustedCaPemFileAndroid(SslCtx, NormalizedClientCaCertificatePath, FailureReason))
#else
	const FTCHARToUTF8 CaCertPathAnsi(*NormalizedClientCaCertificatePath);
	if (SSL_CTX_load_verify_locations(SslCtx, CaCertPathAnsi.Get(), nullptr) != 1)
#endif
	{
#if PLATFORM_ANDROID
		LastError = FString::Printf(TEXT("Failed to load client CA certificate '%s' (normalized: '%s'): %s"), *ClientCaCertificatePath, *NormalizedClientCaCertificatePath, *FailureReason);
#else
		unsigned long ErrCode = ERR_get_error();
		char ErrMsg[256];
		ERR_error_string_n(ErrCode, ErrMsg, sizeof(ErrMsg));
		LastError = FString::Printf(TEXT("Failed to load client CA certificate '%s' (normalized: '%s'): %s"), *ClientCaCertificatePath, *NormalizedClientCaCertificatePath, UTF8_TO_TCHAR(ErrMsg));
#endif
		return false;
	}

	return true;
}

bool FOpenSslConnection::SetPinnedPublicKey(const FString& PublicKeyDigest)
{
	PinnedPublicKeyDigest = PublicKeyDigest;
	return true;
}

FString FOpenSslConnection::GetLastError() const
{
	return LastError;
}

void FOpenSslConnection::StartWorkerThread()
{
	if (WorkerThread != nullptr)
	{
		return;  // Already started
	}

	bStopWorker.store(false);
	SSLWorker = new FSSLWorkerThread(this);
	WorkerThread = FRunnableThread::Create(SSLWorker, TEXT("OpenSSL Worker Thread"));
	
	// Wait a bit for the SSL worker thread to fully start and stabilize
	FPlatformProcess::Sleep(0.05f);  // 50ms delay for worker thread stabilization
}

void FOpenSslConnection::StopSSLWorkerThread()
{
	if (WorkerThread != nullptr)
	{
		bStopWorker.store(true);
		WorkerThread->WaitForCompletion();
		delete WorkerThread;
		WorkerThread = nullptr;
		SSLWorker = nullptr;
	}
}

void FOpenSslConnection::NotifyDisconnected()
{
	if (bDisconnectedNotified.exchange(true))
	{
		return;
	}

	DisconnectedDelegate.Broadcast();
}

bool FOpenSslConnection::CreateSslContext(EObjectDelivererTlsProtocol MinimumProtocol)
{
	LastError.Empty();
	if (!EnsureOpenSslInitialized(LastError))
	{
		return false;
	}

	SslCtx = CreateNativeSslContext(MinimumProtocol);

	if (!SslCtx)
	{
		if (LastError.IsEmpty())
		{
			LastError = TEXT("Failed to create SSL context");
		}
		return false;
	}

	if (!TrustedCaCertificatePath.IsEmpty() && !SetTrustedCaCertificate(TrustedCaCertificatePath))
	{
		SSL_CTX_free(SslCtx);
		SslCtx = nullptr;
		return false;
	}

	if ((!ClientCertificatePath.IsEmpty() || !ClientPrivateKeyPath.IsEmpty()) &&
		!SetClientCertificate(ClientCertificatePath, ClientPrivateKeyPath))
	{
		SSL_CTX_free(SslCtx);
		SslCtx = nullptr;
		return false;
	}

	return true;
}

bool FOpenSslConnection::LoadCertificateAndKey(const FString& CertPath, const FString& KeyPath)
{
	if (CertPath.IsEmpty() || KeyPath.IsEmpty())
	{
		LastError = TEXT("Certificate path or key path is empty");
		return false;
	}

	const FString NormalizedCertPath = NormalizeOpenSslPathForExternalRead(CertPath);
	const FString NormalizedKeyPath = NormalizeOpenSslPathForExternalRead(KeyPath);

	FString CertFailureReason;
#if PLATFORM_ANDROID
	if (!UseCertificatePemFileAndroid(SslCtx, NormalizedCertPath, CertFailureReason))
#else
	if (SSL_CTX_use_certificate_file(SslCtx, TCHAR_TO_UTF8(*NormalizedCertPath), SSL_FILETYPE_PEM) != 1)
#endif
	{
		LastError = FString::Printf(TEXT("Failed to load certificate from '%s' (normalized: '%s')"), *CertPath, *NormalizedCertPath);
#if PLATFORM_ANDROID
		if (!CertFailureReason.IsEmpty())
		{
			LastError += FString::Printf(TEXT(": %s"), *CertFailureReason);
		}
#endif
		return false;
	}

	FString KeyFailureReason;
#if PLATFORM_ANDROID
	if (!UsePrivateKeyPemFileAndroid(SslCtx, NormalizedKeyPath, KeyFailureReason))
#else
	if (SSL_CTX_use_PrivateKey_file(SslCtx, TCHAR_TO_UTF8(*NormalizedKeyPath), SSL_FILETYPE_PEM) != 1)
#endif
	{
		LastError = FString::Printf(TEXT("Failed to load private key from '%s' (normalized: '%s')"), *KeyPath, *NormalizedKeyPath);
#if PLATFORM_ANDROID
		if (!KeyFailureReason.IsEmpty())
		{
			LastError += FString::Printf(TEXT(": %s"), *KeyFailureReason);
		}
#endif
		return false;
	}

	if (SSL_CTX_check_private_key(SslCtx) != 1)
	{
		LastError = TEXT("Private key does not match certificate");
		return false;
	}

	return true;
}

bool FOpenSslConnection::ApplyServerClientAuthSettings()
{
	if (!SslCtx)
	{
		LastError = TEXT("SSL context is not initialized");
		return false;
	}

	const int VerifyMode = GetOpenSslVerifyMode(ClientAuthMode);
	SSL_CTX_set_verify(SslCtx, VerifyMode, nullptr);

	if (ClientAuthMode == EObjectDelivererTlsClientAuthMode::None)
	{
		return true;
	}

	if (ClientCaCertificatePath.IsEmpty())
	{
		LastError = TEXT("Client CA certificate path is required when client authentication is enabled");
		return false;
	}

	return SetClientCaCertificate(ClientCaCertificatePath);
}

bool FOpenSslConnection::SetupSocketBio(FSocket* InSocket)
{
	if (!InSocket)
	{
		LastError = TEXT("Invalid socket");
		return false;
	}

	BIO_METHOD* BioMethod = GetSocketBioMethod();
	if (!BioMethod)
	{
		LastError = TEXT("Failed to create BIO method");
		return false;
	}

	SocketBio = BIO_new(BioMethod);
	if (!SocketBio)
	{
		LastError = TEXT("Failed to create BIO");
		return false;
	}

	BIO_set_data(SocketBio, InSocket);
	// SSL_set_bio() takes ownership of the BIO. When the same BIO is used for both
	// read and write (as here), SSL internally increments the reference count once.
	// SSL_free() will automatically clean up the BIO.
	SSL_set_bio(Ssl, SocketBio, SocketBio);

	return true;
}
