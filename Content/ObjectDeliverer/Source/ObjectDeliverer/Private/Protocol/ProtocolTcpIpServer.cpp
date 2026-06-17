// Copyright 2019 ayumax. All Rights Reserved.
#include "Protocol/ProtocolTcpIpServer.h"
#include "Protocol/ProtocolTcpIpSocket.h"
#include "Common/TcpSocketBuilder.h"
#include "Utils/ODWorkerThread.h"
#include "PacketRule/PacketRule.h"
#include "HAL/RunnableThread.h"
#include "Misc/ScopeLock.h"
#include "Utils/ODLog.h"

UProtocolTcpIpServer::UProtocolTcpIpServer()
{

}

UProtocolTcpIpServer::~UProtocolTcpIpServer()
{

}

void UProtocolTcpIpServer::Initialize(int32 Port)
{
	ListenPort = Port;
}

UProtocolTcpIpServer* UProtocolTcpIpServer::WithReceiveBufferSize(int32 SizeInBytes)
{
	ReceiveBufferSize = SizeInBytes;

	return this;
}

UProtocolTcpIpServer* UProtocolTcpIpServer::WithSendBufferSize(int32 SizeInBytes)
{
	SendBufferSize = SizeInBytes;

	return this;
}

void UProtocolTcpIpServer::Start()
{
	Close();

	IsClosing.Store(false);

	auto socket = FTcpSocketBuilder(TEXT("ObjectDeliverer TcpIpServer"))
		.AsBlocking()
		.BoundToPort(ListenPort)
		.Listening(MaxBacklog)
		.Build();

	if (socket == nullptr)
	{
		OD_LOG(Error, TEXT("UProtocolTcpIpServer::Start failed: could not create listener socket (port=%d)"), ListenPort);
		return;
	}

	ListenerSocket = socket;
	ListenerSocket->SetNonBlocking(true);

	ListenInnerThread = new FODWorkerThread([this] { return OnListen(); });
	ListenThread = FRunnableThread::Create(ListenInnerThread, TEXT("ObjectDeliverer TcpIpSocket ListenThread"));
}

void UProtocolTcpIpServer::Close()
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

	TArray<UProtocolTcpIpSocket*> SocketsToClose;
	{
		FScopeLock lock(&ConnectedSocketsCriticalSection);
		SocketsToClose = MoveTemp(ConnectedSockets);
	}

	for (UProtocolTcpIpSocket* clientSocket : SocketsToClose)
	{
		if (clientSocket)
		{
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

void UProtocolTcpIpServer::Send(const TArray<uint8>& DataBuffer, const FDeliveryDataType& KindOfData) const
{
	TArray<UProtocolTcpIpSocket*> SocketsToSend;
	{
		FScopeLock lock(&ConnectedSocketsCriticalSection);
		SocketsToSend = ConnectedSockets;
	}

	for (int32 Index = 0; Index < SocketsToSend.Num(); ++Index)
	{
		auto* clientSocket = SocketsToSend[Index];
		if (IsValid(clientSocket))
		{
			clientSocket->Send(DataBuffer, KindOfData);
		}
		else
		{
			OD_LOG(Warning, TEXT("UProtocolTcpIpServer::Send client[%d] invalid"), Index);
		}
	}
}

bool UProtocolTcpIpServer::OnListen()
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

			auto clientSocket = NewObject<UProtocolTcpIpSocket>();
			clientSocket->Disconnected.BindUObject(this, &UProtocolTcpIpServer::DisconnectedClient);
			clientSocket->ReceiveData.BindUObject(this, &UProtocolTcpIpServer::ReceiveDataFromClient);
			clientSocket->SetPacketRule(PacketRule->Clone());

			clientSocket->OnConnected(_clientSocket);

			{
				FScopeLock lock(&ConnectedSocketsCriticalSection);
				ConnectedSockets.Add(clientSocket);
			}

			DispatchConnected(clientSocket);
		}
		else if (!bAcceptFailureLogged)
		{
			bAcceptFailureLogged = true;
			OD_LOG(Warning, TEXT("UProtocolTcpIpServer: Accept failed while pending connection"));
		}
	}

	return true;
}

void UProtocolTcpIpServer::DisconnectedClient(const UObjectDelivererProtocol* ClientSocket)
{
	if (IsClosing.Load()) return;

	auto _clientSocket = const_cast<UProtocolTcpIpSocket*>(
		static_cast<const UProtocolTcpIpSocket*>(ClientSocket));
	if (!IsValid(_clientSocket)) return;

	bool bRemoved = false;
	{
		FScopeLock lock(&ConnectedSocketsCriticalSection);
		const int32 foundIndex = ConnectedSockets.Find(_clientSocket);
		if (foundIndex != INDEX_NONE)
		{
			ConnectedSockets.RemoveAt(foundIndex);
			bRemoved = true;
		}
	}

	if (bRemoved)
	{
		DispatchDisconnected(ClientSocket);
	}
}

void UProtocolTcpIpServer::ReceiveDataFromClient(const UObjectDelivererProtocol* ClientSocket, const TArray<uint8>& Buffer)
{
	if (IsClosing.Load()) return;

	DispatchReceiveData(ClientSocket, Buffer);
}
