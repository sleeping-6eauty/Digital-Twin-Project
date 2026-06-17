// Copyright 2019 ayumax. All Rights Reserved.
#include "Protocol/ProtocolTcpIpClientTls.h"
#include "Common/TcpSocketBuilder.h"
#include "Utils/ODWorkerThread.h"
#include "HAL/RunnableThread.h"
#include "OpenSSL/OpenSslConnection.h"
#include "Misc/Paths.h"
#include "Misc/FileHelper.h"
#include "Misc/ScopeLock.h"
#include "HAL/PlatformProcess.h"
#include "HAL/PlatformTime.h"
#include "SocketSubsystem.h"
#include "Sockets.h"
#include "Utils/ODLog.h"

UProtocolTcpIpClientTls::UProtocolTcpIpClientTls()
{
	bVerifyPeer = true;
	bAllowSelfSigned = false;
	MinimumTlsProtocol = EObjectDelivererTlsProtocol::TLSv1_2;
}

UProtocolTcpIpClientTls::~UProtocolTcpIpClientTls()
{
}

void UProtocolTcpIpClientTls::InitializeTls(const FString& IpAddress, int32 Port, bool Retry, bool bAutoConnectAfterDisconnect, EObjectDelivererTlsProtocol MinimumProtocol)
{
	ISocketSubsystem* SocketSubSystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
	OriginalServerIdentity = IpAddress;

	constexpr int32 MaxDnsRetries = 5;
	constexpr float DnsRetryDelaySeconds = 1.0f;
	
	FAddressInfoResult result(*IpAddress, nullptr);
	for (int32 RetryCount = 0; RetryCount < MaxDnsRetries; ++RetryCount)
	{
		result = SocketSubSystem->GetAddressInfo(*IpAddress, nullptr, EAddressInfoFlags::Default, NAME_None);
		if (result.Results.Num() > 0)
		{
			break;
		}
		
		if (RetryCount < MaxDnsRetries - 1)
		{
			OD_LOG(Warning, TEXT("GetAddressInfo failed (attempt %d/%d), retrying in %.1fs..."), 
				RetryCount + 1, MaxDnsRetries, DnsRetryDelaySeconds);
			FPlatformProcess::Sleep(DnsRetryDelaySeconds);
		}
	}
	
	if (result.Results.Num() == 0)
	{
		OD_LOG(Error, TEXT("GetAddressInfo failed after %d attempts"), MaxDnsRetries);
		return;
	}

	FString ip;
	for (const auto& AddressInfo : result.Results)
	{
		const FString CandidateIp = AddressInfo.Address->ToString(false);
		if (ip.IsEmpty())
		{
			ip = CandidateIp;
		}

		// The TLS socket path currently uses IPv4 endpoint parsing.
		// Prefer an IPv4 result when the resolver returns mixed IPv4/IPv6 entries.
		if (CandidateIp.Contains(TEXT(".")) && !CandidateIp.Contains(TEXT(":")))
		{
			ip = CandidateIp;
			break;
		}
	}

	if (ip.IsEmpty())
	{
		OD_LOG(Error, TEXT("GetAddressInfo returned no usable address"));
		return;
	}

	ServerIpAddress = ip;
	ServerPort = Port;
	RetryConnect = Retry;
	this->AutoConnectAfterDisconnect = bAutoConnectAfterDisconnect;
	MinimumTlsProtocol = MinimumProtocol;
}

UProtocolTcpIpClientTls* UProtocolTcpIpClientTls::WithReceiveBufferSize(int32 SizeInBytes)
{
	ReceiveBufferSize = SizeInBytes;
	return this;
}

UProtocolTcpIpClientTls* UProtocolTcpIpClientTls::WithSendBufferSize(int32 SizeInBytes)
{
	SendBufferSize = SizeInBytes;
	return this;
}

UProtocolTcpIpClientTls* UProtocolTcpIpClientTls::WithPinnedPublicKey(const FString& PublicKeyDigest)
{
	bPinnedPublicKeyRequested = true;
	PinnedPublicKeyDigest = PublicKeyDigest;
	return this;
}

static bool IsExpectedTlsHandshakeFailureForClient(const FString& ErrorMessage)
{
	return ErrorMessage.Contains(TEXT("SSL_ERROR_SYSCALL")) ||
		ErrorMessage.Contains(TEXT("SSL_ERROR_ZERO_RETURN")) ||
		ErrorMessage.Contains(TEXT("socket disconnected while waiting for handshake")) ||
		ErrorMessage.Contains(TEXT("timeout while waiting for handshake")) ||
		ErrorMessage.Contains(TEXT("wrong version number")) ||
		ErrorMessage.Contains(TEXT("ssl3_get_record")) ||
		ErrorMessage.Contains(TEXT("tlsv1 alert protocol version")) ||
		ErrorMessage.Contains(TEXT("Certificate verification failed")) ||
		ErrorMessage.Contains(TEXT("certificate required")) ||
		ErrorMessage.Contains(TEXT("data too large for modulus")) ||
		ErrorMessage.Contains(TEXT("block type is not 01")) ||
		ErrorMessage.Contains(TEXT("padding check failed")) ||
		ErrorMessage.Contains(TEXT("Client private key does not match client certificate")) ||
		ErrorMessage.Contains(TEXT("Failed to load client certificate")) ||
		ErrorMessage.Contains(TEXT("Failed to load client private key")) ||
		ErrorMessage.Contains(TEXT("Client certificate path or key path is empty")) ||
		ErrorMessage.Contains(TEXT("unknown ca")) ||
		ErrorMessage.Contains(TEXT("Server identity verification failed")) ||
		ErrorMessage.Contains(TEXT("Self-signed certificates require public key pinning")) ||
		ErrorMessage.Contains(TEXT("Public key pinning failed")) ||
		ErrorMessage.Contains(TEXT("No peer certificate available for pinning verification")) ||
		ErrorMessage.Contains(TEXT("Failed to extract public key from peer certificate")) ||
		ErrorMessage.Contains(TEXT("Failed to serialize public key"));
}

static bool LoadPinnedPublicKeyDigestFromFile(const FString& PublicKeyHashFilePath, FString& OutPinnedPublicKeyDigest)
{
	if (!FPaths::FileExists(PublicKeyHashFilePath))
	{
		OD_LOG(Warning, TEXT("Public key hash file does not exist: %s"), *PublicKeyHashFilePath);
		return false;
	}

	FString FileContent;
	if (!FFileHelper::LoadFileToString(FileContent, *PublicKeyHashFilePath))
	{
		OD_LOG(Error, TEXT("Failed to read public key hash file: %s"), *PublicKeyHashFilePath);
		return false;
	}

	TArray<FString> Lines;
	FileContent.ParseIntoArray(Lines, TEXT("\n"), true);

	auto TryParseDigestLine = [](const FString& Line, FString& OutDigest) -> bool
	{
		const FString Candidate = Line.TrimStartAndEnd();
		TArray<FString> Parts;
		Candidate.ParseIntoArray(Parts, TEXT(":"), true);

		// SHA256 digest of a DER public key: 32 bytes => 32 hex pairs separated by ':'
		if (Parts.Num() != 32)
		{
			return false;
		}

		for (const FString& Part : Parts)
		{
			if (Part.Len() != 2)
			{
				return false;
			}
			for (int32 i = 0; i < Part.Len(); ++i)
			{
				if (!FChar::IsHexDigit(Part[i]))
				{
					return false;
				}
			}
		}

		OutDigest = Candidate;
		return true;
	};

	bool bNextNonEmptyLineIsHash = false;
	for (const FString& Line : Lines)
	{
		const FString TrimmedLine = Line.TrimStartAndEnd();

		if (TrimmedLine.IsEmpty() || TrimmedLine.StartsWith(TEXT("===")) || TrimmedLine.StartsWith(TEXT("Generated by")))
		{
			continue;
		}

		if (TrimmedLine.Equals(TEXT("Public Key Hash:"), ESearchCase::IgnoreCase))
		{
			bNextNonEmptyLineIsHash = true;
			continue;
		}

		if (bNextNonEmptyLineIsHash)
		{
			if (TryParseDigestLine(TrimmedLine, OutPinnedPublicKeyDigest))
			{
				return true;
			}
			// If the next line wasn't a digest, fall back to scanning.
			bNextNonEmptyLineIsHash = false;
		}

		if (TryParseDigestLine(TrimmedLine, OutPinnedPublicKeyDigest))
		{
			return true;
		}
	}

	OD_LOG(Error, TEXT("Could not find public key hash in file: %s"), *PublicKeyHashFilePath);
	return false;
}

static bool IsRetryableSocketErrorForClientConnect(const ESocketErrors Error)
{
	return Error == SE_EWOULDBLOCK ||
		Error == SE_EINPROGRESS ||
		Error == SE_EALREADY;
}

static bool ShouldUseCancelableNonBlockingTcpConnect()
{
#if PLATFORM_ANDROID || PLATFORM_LINUX
	return true;
#else
	return false;
#endif
}

static bool TryConnectWithCancelablePolling(FSocket* Socket, const FIPv4Endpoint& ConnectEndPoint, const TAtomic<bool>& IsClosing)
{
	if (!Socket)
	{
		return false;
	}

	auto* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
	const bool bConnectCallSucceeded = Socket->Connect(ConnectEndPoint.ToInternetAddr().Get());
	if (bConnectCallSucceeded)
	{
		return true;
	}

	ESocketErrors LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;
	ESocketConnectionState ConnectionState = Socket->GetConnectionState();
	bool bPendingConnection = false;
	Socket->HasPendingConnection(bPendingConnection);

	OD_LOG(Log, TEXT("TryConnect pending/fail - SocketError: %d, ConnectionState: %d, Pending: %d"),
		static_cast<int32>(LastSocketError), static_cast<int32>(ConnectionState), bPendingConnection ? 1 : 0);

	const bool bLikelyConnectInProgress =
		IsRetryableSocketErrorForClientConnect(LastSocketError) ||
		LastSocketError == SE_NO_ERROR ||
		bPendingConnection;

	if (!bLikelyConnectInProgress)
	{
		return false;
	}

	constexpr double ConnectAttemptTimeoutSeconds = 15.0;
	constexpr double ConnectPollIntervalSeconds = 0.05;
	const double ConnectStartTimeSeconds = FPlatformTime::Seconds();

	while (!IsClosing.Load())
	{
		if (Socket->Wait(ESocketWaitConditions::WaitForWrite, FTimespan::FromSeconds(ConnectPollIntervalSeconds)))
		{
			ConnectionState = Socket->GetConnectionState();
			LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;
			bPendingConnection = false;
			Socket->HasPendingConnection(bPendingConnection);

			if (ConnectionState == ESocketConnectionState::SCS_ConnectionError)
			{
				OD_LOG(Log, TEXT("TryConnect failed after wait - SocketError: %d, ConnectionState: %d, Pending: %d"),
					static_cast<int32>(LastSocketError), static_cast<int32>(ConnectionState), bPendingConnection ? 1 : 0);
				return false;
			}

			return true;
		}

		ConnectionState = Socket->GetConnectionState();
		if (ConnectionState == ESocketConnectionState::SCS_ConnectionError)
		{
			LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;
			bPendingConnection = false;
			Socket->HasPendingConnection(bPendingConnection);
			OD_LOG(Log, TEXT("TryConnect failed while waiting - SocketError: %d, ConnectionState: %d, Pending: %d"),
				static_cast<int32>(LastSocketError), static_cast<int32>(ConnectionState), bPendingConnection ? 1 : 0);
			return false;
		}

		if ((FPlatformTime::Seconds() - ConnectStartTimeSeconds) >= ConnectAttemptTimeoutSeconds)
		{
			LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;
			bPendingConnection = false;
			Socket->HasPendingConnection(bPendingConnection);
			OD_LOG(Log, TEXT("TryConnect timed out after %.2f seconds - SocketError: %d, ConnectionState: %d, Pending: %d"),
				ConnectAttemptTimeoutSeconds, static_cast<int32>(LastSocketError), static_cast<int32>(ConnectionState), bPendingConnection ? 1 : 0);
			return false;
		}
	}

	OD_LOG(Log, TEXT("TryConnect canceled while waiting for TCP connect completion"));
	return false;
}

UProtocolTcpIpClientTls* UProtocolTcpIpClientTls::WithPinnedPublicKeyFromFile(const FString& PublicKeyHashFilePath)
{
	bPinnedPublicKeyRequested = true;
	if (LoadPinnedPublicKeyDigestFromFile(PublicKeyHashFilePath, PinnedPublicKeyDigest))
	{
		OD_LOG(Log, TEXT("Loaded public key hash from file: %s"), *PublicKeyHashFilePath);
	}
	return this;
}

UProtocolTcpIpClientTls* UProtocolTcpIpClientTls::WithClientCertificate(const FString& CertPath, const FString& KeyPath)
{
	ClientCertificatePath = CertPath;
	ClientPrivateKeyPath = KeyPath;
	return this;
}

UProtocolTcpIpClientTls* UProtocolTcpIpClientTls::WithCertificateVerification()
{
	bVerifyPeer = true;
	return this;
}

UProtocolTcpIpClientTls* UProtocolTcpIpClientTls::WithTrustedCaCertificate(const FString& CaCertificatePath)
{
	TrustedCaCertificatePath = CaCertificatePath;
	return this;
}

UProtocolTcpIpClientTls* UProtocolTcpIpClientTls::WithPeerVerificationDisabled()
{
	bVerifyPeer = false;
	bAllowSelfSigned = false;
	return this;
}

UProtocolTcpIpClientTls* UProtocolTcpIpClientTls::WithAllowSelfSignedCertificates(bool bAllowSelfSignedCertificates)
{
	bAllowSelfSigned = bAllowSelfSignedCertificates;
	return this;
}

void UProtocolTcpIpClientTls::Start()
{
	IsClosing.Store(false);
	
	CloseSocket();

	CreateSocket();

	auto endPoint = GetIP4EndPoint(ServerIpAddress, ServerPort);
	if (!endPoint.Get<0>()) return;

	ConnectEndPoint = endPoint.Get<1>();

	if (!InnerSocket)
	{
		OD_LOG(Error, TEXT("TryConnect failed: InnerSocket is null"));
		return;
	}

	ConnectInnerThread = new FODWorkerThread([this] { return TryConnect(); }, 1.0f);
	ConnectThread = FRunnableThread::Create(ConnectInnerThread, TEXT("ObjectDeliverer UProtocolTcpIpClientTls ConnectThread"));
}

bool UProtocolTcpIpClientTls::TryConnect()
{
	OD_LOG(Log, TEXT("Start TryConnect"));

	if (IsClosing.Load())
	{
		return false;
	}

	if (!InnerSocket)
	{
		if (!IsClosing.Load())
		{
			OD_LOG(Warning, TEXT("TryConnect: InnerSocket is null, recreating socket"));
			CreateSocket();
		}

		if (!InnerSocket)
		{
			OD_LOG(Error, TEXT("TryConnect failed: InnerSocket is null"));
			return RetryConnect;
		}
	}

	const bool bUseCancelableNonBlockingConnect = ShouldUseCancelableNonBlockingTcpConnect();
	InnerSocket->SetNonBlocking(bUseCancelableNonBlockingConnect);

	ESocketConnectionState ConnectionState = InnerSocket->GetConnectionState();
	OD_LOG(Log, TEXT("Socket Connection State before connect: %d"), (int32)ConnectionState);

	if (ConnectionState == ESocketConnectionState::SCS_ConnectionError)
	{
		OD_LOG(Log, TEXT("Recreating socket due to invalid state"));
		InnerSocket->Shutdown(ESocketShutdownMode::ReadWrite);
		CloseInnerSocket();

		CreateSocket();
	}

	if (!InnerSocket)
	{
		return RetryConnect;
	}

	InnerSocket->SetNonBlocking(bUseCancelableNonBlockingConnect);

	ConnectionState = InnerSocket->GetConnectionState();
	// Some non-desktop platforms can report SCS_Connected immediately after socket creation.
	// On those platforms, rely on Connect() result instead of initial state.
#if PLATFORM_WINDOWS || PLATFORM_MAC
	const bool bTrustInitialConnectedState = true;
#else
	const bool bTrustInitialConnectedState = false;
#endif
	bool bTcpConnected = bTrustInitialConnectedState && (ConnectionState == ESocketConnectionState::SCS_Connected);
	if (!bTrustInitialConnectedState && ConnectionState == ESocketConnectionState::SCS_Connected)
	{
		OD_LOG(Warning, TEXT("TryConnect: ignoring initial SCS_Connected state on this platform and attempting explicit Connect()"));
	}

	if (!bTcpConnected)
	{
		if (bUseCancelableNonBlockingConnect)
		{
			bTcpConnected = TryConnectWithCancelablePolling(InnerSocket, ConnectEndPoint, IsClosing);
		}
		else
		{
			const bool bConnectCallSucceeded = InnerSocket->Connect(ConnectEndPoint.ToInternetAddr().Get());
			if (bConnectCallSucceeded)
			{
				bTcpConnected = true;
			}
			else
			{
				ISocketSubsystem* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
				const ESocketErrors LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;

				bool bPendingConnection = false;
				InnerSocket->HasPendingConnection(bPendingConnection);

				OD_LOG(Log, TEXT("TryConnect failed - SocketError: %d, ConnectionState: %d, Pending: %d"),
					(int32)LastSocketError, (int32)InnerSocket->GetConnectionState(), bPendingConnection ? 1 : 0);
			}
		}
	}

	if (bTcpConnected)
	{
		if (IsClosing.Load())
		{
			return false;
		}

		// TLS handshake path expects non-blocking socket behavior.
		InnerSocket->SetNonBlocking(true);

		SslConnection = MakeShared<FOpenSslConnection>();
		if (!SslConnection)
		{
			OD_LOG(Error, TEXT("Failed to create SSL connection object"));
			CloseInnerSocket();
			return RetryConnect;
		}

		if (!bVerifyPeer && PinnedPublicKeyDigest.IsEmpty())
		{
			OD_LOG(Warning, TEXT("INSECURE: Peer certificate verification is disabled and no public key pinning is configured; connection is vulnerable to man-in-the-middle attacks."));
		}
		if (bPinnedPublicKeyRequested && PinnedPublicKeyDigest.IsEmpty())
		{
			OD_LOG(Warning, TEXT("Pinned public key was requested, but no valid pinned key is configured. Check WithPinnedPublicKey() input or WithPinnedPublicKeyFromFile() path."));
			SslConnection.Reset();
			CloseInnerSocket();
			return RetryConnect;
		}

		SslConnection->SetVerifyMode(bVerifyPeer, bAllowSelfSigned);
		if (!TrustedCaCertificatePath.IsEmpty())
		{
			if (!SslConnection->SetTrustedCaCertificate(TrustedCaCertificatePath))
			{
				OD_LOG(Error, TEXT("Failed to configure trusted CA certificate: %s"), *TrustedCaCertificatePath);
				SslConnection.Reset();
				CloseInnerSocket();
				return RetryConnect;
			}
		}

		if (!PinnedPublicKeyDigest.IsEmpty())
		{
			SslConnection->SetPinnedPublicKey(PinnedPublicKeyDigest);
		}

		if (!ClientCertificatePath.IsEmpty() || !ClientPrivateKeyPath.IsEmpty())
		{
			if (!SslConnection->SetClientCertificate(ClientCertificatePath, ClientPrivateKeyPath))
			{
				OD_LOG(Error, TEXT("Failed to configure client certificate/key: %s"), *SslConnection->GetLastError());
				SslConnection.Reset();
				CloseInnerSocket();
				return RetryConnect;
			}
		}

		if (!SslConnection->InitializeForClient(MinimumTlsProtocol))
		{
			const FString LastError = SslConnection->GetLastError();
			if (IsExpectedTlsHandshakeFailureForClient(LastError))
			{
				OD_LOG(Warning, TEXT("Failed to initialize SSL connection: %s"), *LastError);
			}
			else
			{
				OD_LOG(Error, TEXT("Failed to initialize SSL connection: %s"), *LastError);
			}
			SslConnection.Reset();
			CloseInnerSocket();
			return RetryConnect;
		}

		if (!SslConnection->Connect(InnerSocket, OriginalServerIdentity))
		{
			const auto LastError = SslConnection->GetLastError();
			const bool bExpectedConnectFailure = IsExpectedTlsHandshakeFailureForClient(LastError);
			if (bExpectedConnectFailure)
			{
				OD_LOG(Warning, TEXT("SSL handshake failed: %s"), *LastError);
			}
			else
			{
				OD_LOG(Error, TEXT("SSL handshake failed: %s"), *LastError);
			}
			SslConnection.Reset();
			CloseInnerSocket();
			return RetryConnect;
		}

		OnConnected(InnerSocket);

		// Avoid reporting a successful connection if the server rejects immediately
		// after handshake (e.g. mTLS required but client certificate is missing).
		constexpr float ConnectionStabilityWindowSeconds = 0.5f;
		constexpr float ConnectionStabilityPollIntervalSeconds = 0.01f;
		float ElapsedStabilityCheckSeconds = 0.0f;
		while (ElapsedStabilityCheckSeconds < ConnectionStabilityWindowSeconds)
		{
			if (IsClosing.Load())
			{
				return false;
			}

			if (!SslConnection || !SslConnection->IsConnected())
			{
				OD_LOG(Warning, TEXT("TLS connection closed immediately after handshake; treating as connect failure"));
				SslConnection.Reset();
				CloseInnerSocket();
				return RetryConnect;
			}

			if (InnerSocket && InnerSocket->GetConnectionState() == ESocketConnectionState::SCS_ConnectionError)
			{
				OD_LOG(Warning, TEXT("TLS socket entered error state immediately after handshake; treating as connect failure"));
				SslConnection.Reset();
				CloseInnerSocket();
				return RetryConnect;
			}

			FPlatformProcess::Sleep(ConnectionStabilityPollIntervalSeconds);
			ElapsedStabilityCheckSeconds += ConnectionStabilityPollIntervalSeconds;
		}

		DispatchConnected(this);
		return false;
	}

	if (IsClosing.Load())
	{
		return false;
	}

	if (RetryConnect)
	{
		OD_LOG(Log, TEXT("RetryConnect is true, retrying..."));
		return true;
	}

	return false;
}

void UProtocolTcpIpClientTls::OnConnected(FSocket* ConnectionSocket)
{
	// Use parent class's OnConnectedWithSsl to set up SSL connection and callbacks
	OnConnectedWithSsl(ConnectionSocket, SslConnection);
}

void UProtocolTcpIpClientTls::Close()
{
	IsClosing.Store(true);
	StopConnectThread();

	Super::Close();
}

void UProtocolTcpIpClientTls::DispatchDisconnected(const UObjectDelivererProtocol* DisconnectedObject)
{
	Super::DispatchDisconnected(DisconnectedObject);

	if (AutoConnectAfterDisconnect && !IsClosing.Load())
	{
		Start();
	}
}

void UProtocolTcpIpClientTls::CreateSocket()
{
	auto socket = FTcpSocketBuilder(TEXT("ObjectDeliverer TcpIpClientTls"))
			.AsBlocking()
			.WithReceiveBufferSize(ReceiveBufferSize)
			.WithSendBufferSize(SendBufferSize)
			.Build();

	if (socket == nullptr)
	{
		OD_LOG(Log, TEXT("Failed to create socket"));
		return;
	}
		
	InnerSocket = socket;
}

void UProtocolTcpIpClientTls::StopConnectThread()
{
	FODWorkerThread* InnerThreadToClose = ConnectInnerThread;
	FRunnableThread* ThreadToClose = ConnectThread;
	ConnectInnerThread = nullptr;
	ConnectThread = nullptr;

	if (InnerThreadToClose)
	{
		InnerThreadToClose->Stop();
	}

	bool bHasActiveTlsSession = false;
	{
		FScopeLock SslLock(&SslConnectionCriticalSection);
		bHasActiveTlsSession = SslConnection.IsValid() && SslConnection->IsConnected();
	}

	// Interrupt any in-flight TCP connect / TLS handshake wait before joining.
	if (!bHasActiveTlsSession)
	{
		FScopeLock SocketLock(&SocketAccessCriticalSection);
		if (InnerSocket)
		{
			InnerSocket->SetLinger(true, 0);
			InnerSocket->Shutdown(ESocketShutdownMode::ReadWrite);
			InnerSocket->Close();
		}
	}

	if (ThreadToClose)
	{
		ThreadToClose->WaitForCompletion();
		delete ThreadToClose;
	}

	if (!bHasActiveTlsSession)
	{
		FSocket* SocketToDestroy = nullptr;
		{
			FScopeLock SocketLock(&SocketAccessCriticalSection);
			SocketToDestroy = InnerSocket;
			InnerSocket = nullptr;
		}

		if (SocketToDestroy)
		{
			ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->DestroySocket(SocketToDestroy);
		}
	}

	if (InnerThreadToClose)
	{
		delete InnerThreadToClose;
	}
}
