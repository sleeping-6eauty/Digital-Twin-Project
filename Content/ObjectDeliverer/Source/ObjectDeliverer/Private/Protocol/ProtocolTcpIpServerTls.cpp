// Copyright 2019 ayumax. All Rights Reserved.
#include "Protocol/ProtocolTcpIpServerTls.h"
#include "Protocol/ProtocolTcpIpSocketTls.h"
#include "Common/TcpSocketBuilder.h"
#include "Utils/ODWorkerThread.h"
#include "PacketRule/PacketRule.h"
#include "HAL/RunnableThread.h"
#include "Misc/Paths.h"
#include "Misc/FileHelper.h"
#include "HAL/PlatformFileManager.h"
#include "HAL/PlatformMisc.h"

#ifdef UI
	#pragma push_macro("UI")
	#undef UI
	#define OBJECTDELIVERER_RESTORE_UI 1
#endif

#define UI UE_OPENSSL_UI
#define OBJECTDELIVERER_UNDEF_OPENSSL_UI 1

#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509v3.h"

#ifdef OBJECTDELIVERER_UNDEF_OPENSSL_UI
	#undef UI
	#undef OBJECTDELIVERER_UNDEF_OPENSSL_UI
#endif

#ifdef OBJECTDELIVERER_RESTORE_UI
	#pragma pop_macro("UI")
	#undef OBJECTDELIVERER_RESTORE_UI
#endif
#include <cstdio>
#include <stdlib.h>
#include "Utils/ODLog.h"

#if PLATFORM_UNIX
	#include <sys/stat.h>
	#include <cerrno>
#endif

static bool IsExpectedTlsHandshakeFailureForServer(const FString& ErrorMessage)
{
	return ErrorMessage.Contains(TEXT("SSL_ERROR_SYSCALL")) ||
		ErrorMessage.Contains(TEXT("SSL_ERROR_ZERO_RETURN")) ||
		ErrorMessage.Contains(TEXT("timeout while waiting for handshake")) ||
		ErrorMessage.Contains(TEXT("Certificate verification failed")) ||
		ErrorMessage.Contains(TEXT("peer did not return a certificate")) ||
		ErrorMessage.Contains(TEXT("certificate required")) ||
		ErrorMessage.Contains(TEXT("certificate verify failed")) ||
		ErrorMessage.Contains(TEXT("invalid padding")) ||
		ErrorMessage.Contains(TEXT("block type is not 01")) ||
		ErrorMessage.Contains(TEXT("padding check failed")) ||
		ErrorMessage.Contains(TEXT("data too large for modulus")) ||
		ErrorMessage.Contains(TEXT("unknown ca")) ||
		ErrorMessage.Contains(TEXT("Self-signed certificates require public key pinning")) ||
		ErrorMessage.Contains(TEXT("Public key pinning failed")) ||
		ErrorMessage.Contains(TEXT("No peer certificate available for pinning verification")) ||
		ErrorMessage.Contains(TEXT("Failed to extract public key from peer certificate")) ||
		ErrorMessage.Contains(TEXT("Failed to serialize public key"));
}

static EObjectDelivererTlsClientAuthMode ToOpenSslClientAuthMode(EObjectDelivererClientAuthMode Mode)
{
	switch (Mode)
	{
	case EObjectDelivererClientAuthMode::Optional:
		return EObjectDelivererTlsClientAuthMode::Optional;
	case EObjectDelivererClientAuthMode::Required:
		return EObjectDelivererTlsClientAuthMode::Required;
	case EObjectDelivererClientAuthMode::None:
	default:
		return EObjectDelivererTlsClientAuthMode::None;
	}
}

static FString GetTlsEnvironmentVariableCompat(const TCHAR* Name)
{
#if PLATFORM_ANDROID || PLATFORM_IOS
	const FTCHARToUTF8 NameUtf8(Name);
	const char* Value = ::getenv(NameUtf8.Get());
	return Value ? UTF8_TO_TCHAR(Value) : FString();
#else
	return FPlatformMisc::GetEnvironmentVariable(Name);
#endif
}

static void SetTlsEnvironmentVariableCompat(const TCHAR* Name, const TCHAR* Value)
{
#if PLATFORM_ANDROID || PLATFORM_IOS
	const FTCHARToUTF8 NameUtf8(Name);
	if (!Value || Value[0] == TEXT('\0'))
	{
		unsetenv(NameUtf8.Get());
		return;
	}

	const FTCHARToUTF8 ValueUtf8(Value);
	setenv(NameUtf8.Get(), ValueUtf8.Get(), 1);
#else
	FPlatformMisc::SetEnvironmentVar(Name, Value);
#endif
}

UProtocolTcpIpServerTls::UProtocolTcpIpServerTls()
{
}

UProtocolTcpIpServerTls::~UProtocolTcpIpServerTls()
{
}

void UProtocolTcpIpServerTls::InitializeTls(int32 Port, const FString& InCertPath, const FString& InKeyPath, EObjectDelivererTlsProtocol MinimumProtocol)
{
	ListenPort = Port;
	CertificatePath = InCertPath;
	KeyPath = InKeyPath;

	if (!CertificatePath.IsEmpty())
	{
		CertificatePath = IFileManager::Get().ConvertToAbsolutePathForExternalAppForRead(*CertificatePath);
		FPaths::NormalizeFilename(CertificatePath);
	}

	if (!KeyPath.IsEmpty())
	{
		KeyPath = IFileManager::Get().ConvertToAbsolutePathForExternalAppForRead(*KeyPath);
		FPaths::NormalizeFilename(KeyPath);
	}

	if (!ClientCaBundlePath.IsEmpty())
	{
		ClientCaBundlePath = IFileManager::Get().ConvertToAbsolutePathForExternalAppForRead(*ClientCaBundlePath);
		FPaths::NormalizeFilename(ClientCaBundlePath);
	}

	// Make the generated self-signed certificate discoverable by OpenSSL/engine initialization
	if (GetTlsEnvironmentVariableCompat(TEXT("SSL_CERT_FILE")).IsEmpty() && !CertificatePath.IsEmpty())
	{
		SetTlsEnvironmentVariableCompat(TEXT("SSL_CERT_FILE"), *CertificatePath);
	}
	if (GetTlsEnvironmentVariableCompat(TEXT("SSL_CERT_DIR")).IsEmpty() && !CertificatePath.IsEmpty())
	{
		const FString CertDir = FPaths::GetPath(CertificatePath);
		SetTlsEnvironmentVariableCompat(TEXT("SSL_CERT_DIR"), *CertDir);
	}

	MinimumTlsProtocol = MinimumProtocol;
}

UProtocolTcpIpServerTls* UProtocolTcpIpServerTls::WithReceiveBufferSize(int32 SizeInBytes)
{
	ReceiveBufferSize = SizeInBytes;
	return this;
}

UProtocolTcpIpServerTls* UProtocolTcpIpServerTls::WithSendBufferSize(int32 SizeInBytes)
{
	SendBufferSize = SizeInBytes;
	return this;
}

UProtocolTcpIpServerTls* UProtocolTcpIpServerTls::WithClientAuthMode(EObjectDelivererClientAuthMode Mode)
{
	ClientAuthMode = Mode;
	return this;
}

UProtocolTcpIpServerTls* UProtocolTcpIpServerTls::WithClientCaBundle(const FString& CaBundlePath)
{
	ClientCaBundlePath = CaBundlePath;
	if (!ClientCaBundlePath.IsEmpty())
	{
		ClientCaBundlePath = IFileManager::Get().ConvertToAbsolutePathForExternalAppForRead(*ClientCaBundlePath);
		FPaths::NormalizeFilename(ClientCaBundlePath);
	}
	return this;
}

void UProtocolTcpIpServerTls::Start()
{
	Close();

	IsClosing.Store(false);

	auto socket = FTcpSocketBuilder(TEXT("ObjectDeliverer TcpIpServerTls"))
		.AsBlocking()
		.BoundToPort(ListenPort)
		.Listening(MaxBacklog)
		.Build();

	if (socket == nullptr) return;

	ListenerSocket = socket;
	ListenerSocket->SetNonBlocking(true);

	ListenInnerThread = new FODWorkerThread([this] { return OnListen(); });
	ListenThread = FRunnableThread::Create(ListenInnerThread, TEXT("ObjectDeliverer TcpIpServerTls ListenThread"));
}

void UProtocolTcpIpServerTls::Close()
{
	IsClosing.Store(true);

	if (ListenInnerThread)
	{
		ListenInnerThread->Stop();
	}

	// Wait for listen loop to exit before destroying listener socket to avoid invalid FD races.
	if (ListenThread)
	{
		ListenThread->WaitForCompletion();
		delete ListenThread;
		ListenThread = nullptr;
	}

	if (ListenInnerThread)
	{
		delete ListenInnerThread;
		ListenInnerThread = nullptr;
	}

	TArray<UProtocolTcpIpSocketTls*> SocketsToClose;
	{
		FScopeLock lock(&ConnectedSocketsCriticalSection);
		SocketsToClose = MoveTemp(ConnectedSockets);
	}

	for (auto* clientSocket : SocketsToClose)
	{
		if (clientSocket)
		{
			// Stop SSL worker thread.
			clientSocket->Close();
		}
	}

	// Clean up listener socket
	if (ListenerSocket)
	{
		ListenerSocket->Shutdown(ESocketShutdownMode::ReadWrite);
		ListenerSocket->Close();
		ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->DestroySocket(ListenerSocket);
		ListenerSocket = nullptr;
	}
}

void UProtocolTcpIpServerTls::Send(const TArray<uint8>& DataBuffer, const FDeliveryDataType& KindOfData) const
{
	FScopeLock lock(&ConnectedSocketsCriticalSection);
	for (auto clientSocket : ConnectedSockets)
	{
		clientSocket->Send(DataBuffer, KindOfData);
	}
}

bool UProtocolTcpIpServerTls::OnListen()
{
	if (!ListenerSocket) return false;

	if (IsClosing.Load()) return false;

	TSharedRef<FInternetAddr> RemoteAddress = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->CreateInternetAddr();
	bool Pending = false;

	if (ListenerSocket->HasPendingConnection(Pending) && Pending)
	{
		auto _clientSocket = ListenerSocket->Accept(*RemoteAddress, TEXT("ObjectDeliverer Received Socket Connection"));

		if (_clientSocket != nullptr)
		{
			int32 _newReceiveBufferSize;
			_clientSocket->SetReceiveBufferSize(ReceiveBufferSize, _newReceiveBufferSize);
			int32 _newSendBufferSize;
			_clientSocket->SetSendBufferSize(SendBufferSize, _newSendBufferSize);
			_clientSocket->SetNonBlocking(true);

			auto SslConnection = MakeShared<FOpenSslConnection>();
			SslConnection->SetClientAuthMode(ToOpenSslClientAuthMode(ClientAuthMode));
			if (!ClientCaBundlePath.IsEmpty())
			{
				if (!SslConnection->SetClientCaCertificate(ClientCaBundlePath))
				{
					OD_LOG(Error, TEXT("Failed to configure client CA bundle: %s"), *SslConnection->GetLastError());
					_clientSocket->Close();
					ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->DestroySocket(_clientSocket);
					return true;
				}
			}

				if (!SslConnection->InitializeForServer(CertificatePath, KeyPath, MinimumTlsProtocol))
				{
				const FString LastError = SslConnection->GetLastError();
				if (!LastError.IsEmpty())
				{
					OD_LOG(Error, TEXT("Failed to initialize SSL for server connection: %s"), *LastError);
				}
				else
				{
					OD_LOG(Error, TEXT("Failed to initialize SSL for server connection"));
				}
					_clientSocket->SetLinger(true, 0);
					_clientSocket->Shutdown(ESocketShutdownMode::ReadWrite);
					_clientSocket->Close();
					ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->DestroySocket(_clientSocket);
					return true;
				}

				if (!SslConnection->Accept(_clientSocket))
				{
					const FString LastError = SslConnection->GetLastError();
					const bool bExpectedHandshakeFailure = IsExpectedTlsHandshakeFailureForServer(LastError);
					// Handshake rejection from a single client should not be treated as a server-fatal error.
					OD_LOG(Warning, TEXT("SSL handshake failed%s: %s"),
						bExpectedHandshakeFailure ? TEXT("") : TEXT(" (unexpected)"),
						*LastError);
					_clientSocket->SetLinger(true, 0);
					_clientSocket->Shutdown(ESocketShutdownMode::ReadWrite);
					_clientSocket->Close();
					ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->DestroySocket(_clientSocket);
					return true;
				}

			auto clientSocket = NewObject<UProtocolTcpIpSocketTls>();
			clientSocket->Disconnected.BindUObject(this, &UProtocolTcpIpServerTls::DisconnectedClient);
			clientSocket->ReceiveData.BindUObject(this, &UProtocolTcpIpServerTls::ReceiveDataFromClient);

			// Set PacketRule BEFORE OnConnectedWithSsl so that the callback is properly configured
			clientSocket->SetPacketRule(PacketRule->Clone());

			clientSocket->OnConnectedWithSsl(_clientSocket, SslConnection);

			{
				FScopeLock lock(&ConnectedSocketsCriticalSection);
				ConnectedSockets.Add(clientSocket);
			}

			DispatchConnected(clientSocket);
		}
	}

	return true;
}

void UProtocolTcpIpServerTls::DisconnectedClient(const UObjectDelivererProtocol* ClientSocket)
{
	if (IsClosing.Load()) return;

	auto _clientSocket = const_cast<UProtocolTcpIpSocketTls*>(
		static_cast<const UProtocolTcpIpSocketTls*>(ClientSocket));
	if (!IsValid(_clientSocket)) return;

	int32 foundIndex;
	{
		FScopeLock lock(&ConnectedSocketsCriticalSection);
		foundIndex = ConnectedSockets.Find(_clientSocket);
		if (foundIndex != INDEX_NONE)
		{
			ConnectedSockets.RemoveAt(foundIndex);
		}
	}

	if (foundIndex != INDEX_NONE)
	{
		DispatchDisconnected(ClientSocket);
	}
}

void UProtocolTcpIpServerTls::ReceiveDataFromClient(const UObjectDelivererProtocol* ClientSocket, const TArray<uint8>& Buffer)
{
	if (IsClosing.Load()) return;

	DispatchReceiveData(ClientSocket, Buffer);
}
