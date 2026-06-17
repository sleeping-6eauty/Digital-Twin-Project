// Copyright 2019 ayumax. All Rights Reserved.
#include "Protocol/ProtocolUdpSocketReceiver.h"
#include "PacketRule/PacketRule.h"
#include "Protocol/ProtocolUdpSocket.h"
#include "Utils/ODWorkerThread.h"
#include "HAL/RunnableThread.h"
#include "Common/UdpSocketBuilder.h"
#include "Utils/ODLog.h"
#include "Misc/ScopeLock.h"

UProtocolUdpSocketReceiver::UProtocolUdpSocketReceiver()
{

}

UProtocolUdpSocketReceiver::~UProtocolUdpSocketReceiver()
{

}	

void UProtocolUdpSocketReceiver::InitializeWithReceiver(int32 _BoundPort)
{
	BoundPort = _BoundPort;
}

UProtocolUdpSocketReceiver* UProtocolUdpSocketReceiver::WithReceiveBufferSize(int32 SizeInBytes)
{
	ReceiveBufferSize = SizeInBytes;

	return this;
}


void UProtocolUdpSocketReceiver::Start()
{
	bIsClosing.Store(false);
	IsSelfClose = false;
	ReceiveBuffer.SetLength(0);
	ConnectedSockets.Reset();

	InnerSocket = FUdpSocketBuilder(TEXT("ObjectDeliverer UdpSocket"))
		.WithReceiveBufferSize(ReceiveBufferSize)
		.BoundToPort(BoundPort)
		.Build();

	if (InnerSocket)
	{
		SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
		if (!SocketSubsystem)
		{
			OD_LOG(Error, TEXT("UProtocolUdpSocketReceiver::Start failed: SocketSubsystem is null"));
			CloseInnerSocket();
			return;
		}

		CurrentInnerThread = new FODWorkerThread([this]
			{
				return ReceivedData();
			});
		CurrentThread = FRunnableThread::Create(CurrentInnerThread, TEXT("ObjectDeliverer UDPSocket PollingThread"));

		DispatchConnected(this);
	}
	else
	{
		OD_LOG(Error, TEXT("UProtocolUdpSocketReceiver::Start failed: could not create UDP socket (port=%d)"), BoundPort);
	}
}

void UProtocolUdpSocketReceiver::Close()
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

		{
			FScopeLock SocketLock(&SocketAccessCriticalSection);
			if (InnerSocket)
			{
				// Wake the receiver thread without invalidating the socket until after join.
				InnerSocket->Shutdown(ESocketShutdownMode::ReadWrite);
			}
		}

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

	ConnectedSockets.Reset();

	CloseInnerSocket();
}


bool UProtocolUdpSocketReceiver::ReceivedData()
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
		return false;
	}

	if (!Socket->Wait(ESocketWaitConditions::WaitForRead, FTimespan::FromMilliseconds(10)))
	{
		if (bIsClosing.Load())
		{
			return false;
		}
		return true;
	}

	uint32 Size = 0;
	while (Socket->HasPendingData(Size))
	{
		ReceiveBuffer.SetLength(Size);

		TSharedRef<FInternetAddr> Sender = SocketSubsystem->CreateInternetAddr();
		int32 Read = 0;

		if (!Socket->RecvFrom(ReceiveBuffer.AsSpan().Buffer, ReceiveBuffer.GetLength(), Read, *Sender))
		{
			if (!IsSelfClose && !bIsClosing.Load())
			{
				OD_LOG(Warning, TEXT("UProtocolUdpSocketReceiver: Failed to receive UDP data, disconnecting"));
				CloseInnerSocket();
				DispatchDisconnected(this);
			}
			return false;
		}

		ReceiveBuffer.SetLength(Read);

		if (ReceiveBuffer.GetLength() > 0)
		{
			auto ip = FIPv4Endpoint(Sender);

			if (!ConnectedSockets.Contains(ip))
			{
				auto udpSender = NewObject<UProtocolUdpSocket>(this);
				udpSender->Initialize(ip);
				udpSender->SetPacketRule(PacketRule->Clone());
				udpSender->ReceiveData.BindUObject(this, &UProtocolUdpSocketReceiver::ReceiveDataFromClient);
				ConnectedSockets.Add(ip, udpSender);
			}

			FScopeLock lock(&ct);
			ConnectedSockets[ip]->NotifyReceived(ReceiveBuffer.AsSpan());

			ReceiveBuffer.Clear();
		}
	}

	return true;
}


void UProtocolUdpSocketReceiver::ReceiveDataFromClient(const UObjectDelivererProtocol* ClientSocket, const TArray<uint8>& Buffer)
{
	DispatchReceiveData(ClientSocket, Buffer);
}
