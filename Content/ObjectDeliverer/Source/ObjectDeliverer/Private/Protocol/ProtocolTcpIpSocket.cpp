// Copyright 2019 ayumax. All Rights Reserved.
#include "Protocol/ProtocolTcpIpSocket.h"
#include "Common/TcpSocketBuilder.h"
#include "Utils/ODWorkerThread.h"
#include "HAL/RunnableThread.h"
#include "PacketRule/PacketRule.h"
#include "Utils/ODLog.h"
#include "Misc/ScopeLock.h"

UProtocolTcpIpSocket::UProtocolTcpIpSocket()
{

}

UProtocolTcpIpSocket::~UProtocolTcpIpSocket()
{
}


void UProtocolTcpIpSocket::Close()
{
	CloseSocket();
}


void UProtocolTcpIpSocket::CloseSocket()
{
	if (bIsClosing.Exchange(true))
	{
		return;
	}

	IsSelfClose = true;

	FRunnableThread* ThreadToClose = nullptr;
	FODWorkerThread* InnerThreadToClose = nullptr;
	{
		FScopeLock lock(&ct);
		ThreadToClose = CurrentThread;
		CurrentThread = nullptr;
		InnerThreadToClose = CurrentInnerThread;
		CurrentInnerThread = nullptr;
	}

	if (ThreadToClose)
	{
		if (InnerThreadToClose)
		{
			InnerThreadToClose->Stop();
		}

		// Request socket shutdown first so Wait()/Recv() can exit without invalidating the FD.
		{
			FScopeLock SocketLock(&SocketAccessCriticalSection);
			if (InnerSocket)
			{
				InnerSocket->Shutdown(ESocketShutdownMode::ReadWrite);
			}
		}

		// Do not use Kill(true) here. Forcibly terminating the receive thread while it holds
		// plugin/UE locks can permanently deadlock teardown on mobile.
		ThreadToClose->WaitForCompletion();
		delete ThreadToClose;
	}
	else if (InnerThreadToClose)
	{
		InnerThreadToClose->Stop();
	}

	if (InnerThreadToClose)
	{
		delete InnerThreadToClose;
	}

	CloseInnerSocket();
}

void UProtocolTcpIpSocket::Send(const TArray<uint8>& DataBuffer, const FDeliveryDataType& KindOfData) const
{
	if (!InnerSocket) return;

	PacketRule->MakeSendPacket(DataBuffer, KindOfData);
}

void UProtocolTcpIpSocket::OnConnected(FSocket* ConnectionSocket)
{
	bIsClosing.Store(false);
	IsSelfClose = false;
	ConsecutiveReadableNoDataCount = 0;

	if (ConnectionSocket)
	{
		ConnectionSocket->SetNonBlocking(true);
	}

	{
		FScopeLock SocketLock(&SocketAccessCriticalSection);
		InnerSocket = ConnectionSocket;
	}
	StartPollilng();
}

void UProtocolTcpIpSocket::StartPollilng()
{
	ReceiveBuffer.SetLength(0);
	auto* NewInnerThread = new FODWorkerThread([this]
	{
		return ReceivedData();
	});
	auto* NewThread = FRunnableThread::Create(NewInnerThread, TEXT("ObjectDeliverer TcpIpSocket PollingThread"));
	{
		FScopeLock lock(&ct);
		CurrentInnerThread = NewInnerThread;
		CurrentThread = NewThread;
	}
}

bool UProtocolTcpIpSocket::ReceivedData()
{
	if (bIsClosing.Load())
	{
		return false;
	}

	FSocket* Socket = nullptr;
	{
		FScopeLock SocketLock(&SocketAccessCriticalSection);
		Socket = InnerSocket;
	}

	if (!Socket)
	{
		OD_LOG(Warning, TEXT("UProtocolTcpIpSocket::ReceivedData called with null socket"));
		DispatchDisconnected(this);
		return false;
	}

	// Block waiting for some data
	if (!Socket->Wait(ESocketWaitConditions::WaitForRead, FTimespan::FromSeconds(0.1)))
	{
		ConsecutiveReadableNoDataCount = 0;
		if (bIsClosing.Load())
		{
			return false;
		}
		const auto ConnectionState = Socket->GetConnectionState();
		if (ConnectionState == SCS_ConnectionError || ConnectionState == SCS_NotConnected)
		{
			if (!IsSelfClose && !bIsClosing.Load())
			{
				OD_LOG(Warning, TEXT("UProtocolTcpIpSocket: Connection error while waiting for data, disconnecting"));
				CloseInnerSocket();
				DispatchDisconnected(this);
			}
			return false;
		}
		return true;
	}

	uint32 Size = 0;
	bool bReceivedAnyData = false;
	while (Socket->HasPendingData(Size))
	{
		if (bIsClosing.Load())
		{
			return false;
		}

		ReceiveBuffer.SetLength(Size);

		int32 Read = 0;
		if (!Socket->Recv(ReceiveBuffer.AsSpan().Buffer, ReceiveBuffer.GetLength(), Read))
		{
			if (!IsSelfClose && !bIsClosing.Load())
			{
				OD_LOG(Warning, TEXT("UProtocolTcpIpSocket: Failed to receive data, disconnecting"));
				CloseInnerSocket();
				DispatchDisconnected(this);
			}
			return false;
		}

		if (Read <= 0)
		{
			if (!IsSelfClose && !bIsClosing.Load())
			{
				OD_LOG(Warning, TEXT("UProtocolTcpIpSocket: Socket closed while receiving data, disconnecting"));
				CloseInnerSocket();
				DispatchDisconnected(this);
			}
			return false;
		}

		ReceiveBuffer.SetLength(Read);
		bReceivedAnyData = true;
		ConsecutiveReadableNoDataCount = 0;

		while(ReceiveBuffer.GetLength() > 0)
		{
			const int32 wantSize = PacketRule->GetWantSize();

			if (wantSize > 0)
			{
				if (ReceiveBuffer.GetLength() < wantSize) return true;
			}

			const auto receiveSize = wantSize == 0 ? ReceiveBuffer.GetLength() : wantSize;

			PacketRule->NotifyReceiveData(ReceiveBuffer.AsSpan(0, receiveSize).ToArray());

			ReceiveBuffer.RemoveRangeFromStart(0, receiveSize);
		}		
	}

	// Wait returned readable but no pending data. Treat connection errors as disconnects.
	if (!bReceivedAnyData)
	{
		// Some platforms do not update HasPendingData on peer close. Probe with a peek only after WaitForRead signaled readable.
		int32 PeekBytesRead = 0;
		uint8 Dummy = 0;
		const bool bPeekResult = Socket->Recv(&Dummy, 1, PeekBytesRead, ESocketReceiveFlags::Peek);
		if (!bPeekResult || PeekBytesRead <= 0)
		{
			const auto ConnectionState = Socket->GetConnectionState();
			auto* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
			const ESocketErrors LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;
			const bool bRetryableNoData =
				LastSocketError == SE_EWOULDBLOCK ||
				LastSocketError == SE_EINPROGRESS ||
				LastSocketError == SE_EALREADY;
			const bool bConnectedWithNoSocketError =
				ConnectionState == SCS_Connected && LastSocketError == SE_NO_ERROR;
			const bool bTransientReadableWithoutData =
				ConnectionState == SCS_Connected && bRetryableNoData;

			if (bTransientReadableWithoutData)
			{
				ConsecutiveReadableNoDataCount = 0;
				return true;
			}

#if PLATFORM_ANDROID || PLATFORM_IOS
			// Mobile socket stacks can spuriously signal readability and then return
			// no bytes/no error while the connection is still alive. Debounce these events,
			// but do not suppress them forever or peer-close detection may never fire.
			if (bConnectedWithNoSocketError)
			{
				ConsecutiveReadableNoDataCount++;
				if (ConsecutiveReadableNoDataCount < 20)
				{
					return true;
				}
			}
			else
			{
				ConsecutiveReadableNoDataCount = 0;
			}
#else
			// Some platforms can report a readable socket and then return no bytes with no error
			// during teardown. Treat the first few occurrences as transient to avoid Android false positives,
			// then fall through and disconnect if it keeps repeating.
			if (bConnectedWithNoSocketError)
			{
				ConsecutiveReadableNoDataCount++;
				if (ConsecutiveReadableNoDataCount < 3)
				{
					return true;
				}
			}
			else
			{
				ConsecutiveReadableNoDataCount = 0;
			}
#endif

			if (!IsSelfClose && !bIsClosing.Load())
			{
				OD_LOG(Warning, TEXT("UProtocolTcpIpSocket: Socket closed while peeking after WaitForRead, disconnecting"));
				CloseInnerSocket();
				DispatchDisconnected(this);
			}
			return false;
		}

		ConsecutiveReadableNoDataCount = 0;

		const auto ConnectionState = Socket->GetConnectionState();
		if (ConnectionState == SCS_ConnectionError || ConnectionState == SCS_NotConnected)
		{
			if (!IsSelfClose && !bIsClosing.Load())
			{
				OD_LOG(Warning, TEXT("UProtocolTcpIpSocket: Connection closed while waiting for data, disconnecting"));
				CloseInnerSocket();
				DispatchDisconnected(this);
			}
			return false;
		}
	}

	return true;
}

void UProtocolTcpIpSocket::RequestSend(const TArray<uint8>& DataBuffer, const FDeliveryDataType& DataType)
{
	SendToConnected(DataBuffer);
}

bool UProtocolTcpIpSocket::GetIPAddress(TArray<uint8>& IPAddress)
{
	FScopeLock SocketLock(&SocketAccessCriticalSection);
	if (InnerSocket == nullptr) return false;

	TSharedPtr<FInternetAddr> Addr = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->CreateInternetAddr();
	InnerSocket->GetPeerAddress(*Addr);
	IPAddress.SetNum(0);
	IPAddress = Addr->GetRawIp();

	return true;
}

bool UProtocolTcpIpSocket::GetIPAddressInString(FString& IPAddress)
{
	FScopeLock SocketLock(&SocketAccessCriticalSection);
	if (InnerSocket == nullptr) return false;

	TSharedPtr<FInternetAddr> Addr = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->CreateInternetAddr();
	InnerSocket->GetPeerAddress(*Addr);

	IPAddress = Addr->ToString(false);

	return true;
}
