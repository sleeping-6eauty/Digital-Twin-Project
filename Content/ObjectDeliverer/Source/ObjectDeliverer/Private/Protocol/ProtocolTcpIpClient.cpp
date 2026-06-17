// Copyright 2019 ayumax. All Rights Reserved.
#include "Protocol/ProtocolTcpIpClient.h"
#include "Common/TcpSocketBuilder.h"
#include "Utils/ODWorkerThread.h"
#include "HAL/RunnableThread.h"
#include "HAL/PlatformProcess.h"
#include "HAL/PlatformTime.h"
#include "Utils/ODLog.h"

UProtocolTcpIpClient::UProtocolTcpIpClient()
{

}

UProtocolTcpIpClient::~UProtocolTcpIpClient()
{
	
}

void UProtocolTcpIpClient::Initialize(const FString& IpAddress, int32 Port, bool Retry/* = false*/, bool _AutoConnectAfterDisconnect/* = false*/)
{
	ISocketSubsystem* SocketSubSystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);

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
	auto ip = result.Results[0].Address->ToString(false);

	ServerIpAddress = ip;
	ServerPort = Port;
	RetryConnect = Retry;
	AutoConnectAfterDisconnect = _AutoConnectAfterDisconnect;
}

UProtocolTcpIpClient* UProtocolTcpIpClient::WithReceiveBufferSize(int32 SizeInBytes)
{
	ReceiveBufferSize = SizeInBytes;

	return this;
}

UProtocolTcpIpClient* UProtocolTcpIpClient::WithSendBufferSize(int32 SizeInBytes)
{
	SendBufferSize = SizeInBytes;

	return this;
}

void UProtocolTcpIpClient::Start()
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
	ConnectThread = FRunnableThread::Create(ConnectInnerThread, TEXT("ObjectDeliverer UProtocolTcpIpClient ConnectThread"));
}

bool UProtocolTcpIpClient::TryConnect()
{
	OD_LOG(Log, TEXT("Start TryConnect"));

	if (IsClosing.Load())
	{
		return false;
	}
	
	if (!InnerSocket)
	{
		OD_LOG(Error, TEXT("TryConnect failed: InnerSocket is null"));
		return false;
	}

	// Check socket state
	ESocketConnectionState ConnectionState = InnerSocket->GetConnectionState();
	OD_LOG(Log, TEXT("Socket Connection State before connect: %d"), (int32)ConnectionState);

	// Recreate socket if in error or connected state
	if (ConnectionState == ESocketConnectionState::SCS_ConnectionError || 
		ConnectionState == ESocketConnectionState::SCS_Connected)
	{
		OD_LOG(Log, TEXT("Recreating socket due to invalid state"));
		InnerSocket->Shutdown(ESocketShutdownMode::ReadWrite);
		InnerSocket->Close();
		
		CreateSocket();
	}

	if (!InnerSocket)
	{
		return false;
	}
	
	// -------------------------------------------------------------------------------------
	// Skip state check on Linux due to bug where GetConnectionState() returns Connected immediately after socket creation
	// -------------------------------------------------------------------------------------
#if PLATFORM_WINDOWS || PLATFORM_MAC
	// Recheck socket state before attempting connection
	ConnectionState = InnerSocket->GetConnectionState();
	if (ConnectionState != ESocketConnectionState::SCS_NotConnected)
	{
		OD_LOG(Log, TEXT("Socket is not in NotConnected state, skipping connect attempt"));
		return RetryConnect;
	}
#endif
	
	if (InnerSocket->Connect(ConnectEndPoint.ToInternetAddr().Get()))
	{
		if (IsClosing.Load())
		{
			return false;
		}

		OD_LOG(Log, TEXT("TryConnect success"));
		OnConnected(InnerSocket);
		DispatchConnected(this);
		return false;
	}
	else
	{
		int32 ErrorCode = FPlatformMisc::GetLastError();
		ConnectionState = InnerSocket->GetConnectionState();
		
		bool PendingConnection = false;
		InnerSocket->HasPendingConnection(PendingConnection);
		
		OD_LOG(Log, TEXT("TryConnect failed - Error: %d, ConnectionState: %d, Pending: %d"), 
			ErrorCode, (int32)ConnectionState, PendingConnection ? 1 : 0);
			
		if (RetryConnect)
		{
			OD_LOG(Log, TEXT("RetryConnect is true, retrying..."));
			return true;
		}
	}

	return false;
}

void UProtocolTcpIpClient::Close()
{
	IsClosing.Store(true);

	if (ConnectInnerThread)
	{
		ConnectInnerThread->Stop();
	}

	if (ConnectThread)
	{
		// Connect() can block on some platforms, so keep Kill(true) here after requesting cooperative stop.
		ConnectThread->Kill(true);
		delete ConnectThread;
		ConnectThread = nullptr;
	}

	if (ConnectInnerThread)
	{
		delete ConnectInnerThread;
		ConnectInnerThread = nullptr;
	}

	Super::Close();
}


void UProtocolTcpIpClient::DispatchDisconnected(const UObjectDelivererProtocol* DisconnectedObject)
{
	Super::DispatchDisconnected(DisconnectedObject);

	if (AutoConnectAfterDisconnect && !IsClosing.Load())
	{
		Start();
	}
}

void UProtocolTcpIpClient::CreateSocket()
{
	auto socket = FTcpSocketBuilder(TEXT("ObjectDeliverer TcpIpClient"))
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
