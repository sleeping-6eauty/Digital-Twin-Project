// Copyright 2019 ayumax. All Rights Reserved.
#include "Protocol/ProtocolTcpIpSocketTls.h"
#include "PacketRule/PacketRule.h"
#include "Utils/ODLog.h"

UProtocolTcpIpSocketTls::UProtocolTcpIpSocketTls()
{
}

UProtocolTcpIpSocketTls::~UProtocolTcpIpSocketTls()
{
}

void UProtocolTcpIpSocketTls::SetSslConnection(TSharedPtr<FOpenSslConnection> InSslConnection)
{
	FScopeLock lock(&SslConnectionCriticalSection);
	SslConnection = InSslConnection;
}

void UProtocolTcpIpSocketTls::Close()
{
	// Mark as closing first using atomic to prevent deadlock with OnSslDisconnected
	bIsSslClosing.store(true);
	IsSelfClose = true;

	// Get the connection pointer under lock, then close it outside the lock
	// This prevents deadlock: Close() holds lock -> WaitForCompletion() -> 
	// Worker thread calls OnSslDisconnected() -> tries to acquire same lock
	TSharedPtr<FOpenSslConnection> SslConnectionCopy;
	{
		FScopeLock lock(&SslConnectionCriticalSection);
		SslConnectionCopy = SslConnection;
		SslConnection.Reset();
	}

	// Close SSL connection outside the critical section to avoid deadlock
	if (SslConnectionCopy)
	{
		SslConnectionCopy->Close();
	}

	Super::Close();
}

void UProtocolTcpIpSocketTls::Send(const TArray<uint8>& DataBuffer, const FDeliveryDataType& KindOfData) const
{
	{
		FScopeLock lock(&SslConnectionCriticalSection);
		if (!SslConnection || !SslConnection->IsConnected())
		{
			OD_LOG(Warning, TEXT("SocketTLS: SSL connection not established, cannot send data"));
			return;
		}
	}

	// Process the data through PacketRule first, then send via SSL
	// MakeSendPacket will call RequestSend callback with the formatted data
	// Note: Lock is released before calling MakeSendPacket to avoid deadlock with RequestSend
	PacketRule->MakeSendPacket(DataBuffer, KindOfData);
}

void UProtocolTcpIpSocketTls::RequestSend(const TArray<uint8>& DataBuffer, const FDeliveryDataType& DataType)
{
	FScopeLock lock(&SslConnectionCriticalSection);
	if (!SslConnection)
	{
		OD_LOG(Warning, TEXT("SocketTLS: SSL connection not established, cannot send data"));
		return;
	}

	// The new SSL worker thread architecture handles sending asynchronously
	// Just queue the data and return
	SslConnection->Send(DataBuffer.GetData(), DataBuffer.Num());
}

void UProtocolTcpIpSocketTls::OnConnectedWithSsl(FSocket* ConnectionSocket, TSharedPtr<FOpenSslConnection> InSslConnection)
{
	bIsClosing.Store(false);

	FScopeLock lock(&SslConnectionCriticalSection);
	bIsSslClosing.store(false);
	IsSelfClose = false;
	SslConnection = InSslConnection;

	// Set up callback for received data from SSL worker thread BEFORE starting the worker
	if (SslConnection)
	{
		SslConnection->OnDataReceived().AddUObject(this, &UProtocolTcpIpSocketTls::OnSSLDataReceived);
		SslConnection->OnDisconnected().AddUObject(this, &UProtocolTcpIpSocketTls::OnSslDisconnected);
		// Now start the SSL worker thread after callback is registered
		SslConnection->StartWorkerThread();
	}

	// Store the socket, but DON'T start the polling thread.
	// The SSL worker thread handles all SSL operations now.
	{
		FScopeLock SocketLock(&SocketAccessCriticalSection);
		InnerSocket = ConnectionSocket;
	}
}

bool UProtocolTcpIpSocketTls::ReceivedData()
{
	TSharedPtr<FOpenSslConnection> SslConnectionCopy;
	bool HasValidSocket;

	{
		FScopeLock lock(&SslConnectionCriticalSection);
		SslConnectionCopy = SslConnection;
		HasValidSocket = InnerSocket != nullptr;
	}

	if (!HasValidSocket)
	{
		OD_LOG(Warning, TEXT("SocketTLS ReceivedData: InnerSocket is null, disconnecting"));
		DispatchDisconnected(this);
		return false;
	}

	if (!SslConnectionCopy || !SslConnectionCopy->IsConnected())
	{
		OD_LOG(Warning, TEXT("SocketTLS ReceivedData: SSL connection not valid, disconnecting"));
		DispatchDisconnected(this);
		return false;
	}

	// Check if there's any data available on the socket before calling SSL_read
	// This prevents SSL_read from being called when there's no data, which causes
	// "wrong version number" errors in non-blocking mode
	uint32 PendingDataSize = 0;
	if (!InnerSocket->HasPendingData(PendingDataSize) || PendingDataSize == 0)
	{
		// No data available, just continue polling
		return true;
	}

	uint8 Dummy;
	int32 BytesRead = SslConnectionCopy->Recv(&Dummy, 1);
	if (BytesRead < 0)
	{
		return true;  // Continue polling
	}

	if (BytesRead == 0)
	{
		return true;
	}

	FScopeLock lock(&ct);
	ReceiveBuffer.Add(ODByteSpan(&Dummy, 1));

	uint32 PendingSize = 0;
	while (true)
	{
		uint8 TempBuffer[4096];
		int32 TempBytes = SslConnectionCopy->Recv(TempBuffer, 4096);

		if (TempBytes < 0)
		{
			break;
		}

		if (TempBytes > 0)
		{
			ReceiveBuffer.Add(ODByteSpan(TempBuffer, TempBytes));
		}

		if (TempBytes < 4096)
		{
			break;
		}
	}

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

	return true;
}

void UProtocolTcpIpSocketTls::OnSSLDataReceived(const uint8* Data, int32 Size)
{
	// This is called from the SSL worker thread when data is received
	// Add data to the receive buffer for processing by PacketRule
	FScopeLock lock(&ct);

	ReceiveBuffer.Add(ODByteSpan(const_cast<uint8*>(Data), Size));

	// Process the received data through PacketRule
	// PacketRule may need multiple reads (e.g., size header then body)
	while (ReceiveBuffer.GetLength() > 0)
	{
		const int32 wantSize = PacketRule->GetWantSize();

		if (wantSize > 0)
		{
			if (ReceiveBuffer.GetLength() < wantSize) return;
		}

		const auto receiveSize = wantSize == 0 ? ReceiveBuffer.GetLength() : wantSize;

		// Extract exactly the requested amount and pass to PacketRule
		TArray<uint8> ExtractedData = ReceiveBuffer.AsSpan(0, receiveSize).ToArray();
		ReceiveBuffer.RemoveRangeFromStart(0, receiveSize);

	PacketRule->NotifyReceiveData(ExtractedData);
	}
}

void UProtocolTcpIpSocketTls::OnSslDisconnected()
{
	// Check atomic flag first without locking to prevent deadlock
	// Close() sets this flag before calling WaitForCompletion()
	if (bIsSslClosing.load())
	{
		return;
	}

	// Also check IsSelfClose with lock for legacy compatibility
	{
		FScopeLock lock(&SslConnectionCriticalSection);
		if (IsSelfClose) return;
		// Mark as self-closing to prevent multiple dispatch attempts
		IsSelfClose = true;
	}

	CloseInnerSocket();
	DispatchDisconnected(this);
}
