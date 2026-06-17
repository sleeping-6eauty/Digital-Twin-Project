// Copyright 2019 ayumax. All Rights Reserved.
#include "Protocol/ProtocolSocketBase.h"
#include "Misc/OutputDeviceRedirector.h"
#include "Sockets.h"
#include "SocketSubsystem.h"
#include "Interfaces/IPv4/IPv4Address.h"
#include "Interfaces/IPv4/IPv4Endpoint.h"
#include "Utils/ODLog.h"
#include "Misc/ScopeLock.h"

UProtocolSocketBase::UProtocolSocketBase()
{

}

UProtocolSocketBase::~UProtocolSocketBase()
{

}

void UProtocolSocketBase::CloseInnerSocket()
{
	FSocket* SocketToClose = nullptr;
	{
		FScopeLock lock(&SocketAccessCriticalSection);
		if (!InnerSocket) return;

		SocketToClose = InnerSocket;
		InnerSocket = nullptr;
	}

	SocketToClose->Shutdown(ESocketShutdownMode::ReadWrite);

#if PLATFORM_ANDROID || PLATFORM_IOS
	// Force an immediate reset on mobile to make peer disconnect detection more reliable.
	SocketToClose->SetLinger(true, 0);
#endif

	SocketToClose->Close();
	ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM)->DestroySocket(SocketToClose);
}

void UProtocolSocketBase::SendTo(const TArray<uint8>& DataBuffer, const FIPv4Endpoint& EndPoint) const 
{
	FScopeLock lock(&SocketAccessCriticalSection);
	if (!InnerSocket) return;

	int32 BytesSent;
	InnerSocket->SendTo(DataBuffer.GetData(), DataBuffer.Num(), BytesSent, EndPoint.ToInternetAddr().Get());
}

void UProtocolSocketBase::SendToConnected(const TArray<uint8>& DataBuffer) const
{
	FScopeLock lock(&SocketAccessCriticalSection);
	if (!InnerSocket) return;

	const uint8* Data = DataBuffer.GetData();
	const int32 TotalBytes = DataBuffer.Num();
	int32 Offset = 0;
	int32 RetryCount = 0;

	while (Offset < TotalBytes)
	{
		int32 BytesSent = 0;
		const bool bSent = InnerSocket->Send(Data + Offset, TotalBytes - Offset, BytesSent);
		if (bSent && BytesSent > 0)
		{
			Offset += BytesSent;
			RetryCount = 0;
			continue;
		}

		auto* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
		const ESocketErrors LastSocketError = SocketSubsystem ? SocketSubsystem->GetLastErrorCode() : SE_NO_ERROR;
		const bool bRetryable =
			LastSocketError == SE_EWOULDBLOCK ||
			LastSocketError == SE_EINPROGRESS ||
			LastSocketError == SE_EALREADY;

		if (bRetryable && RetryCount < 10)
		{
			RetryCount++;
			InnerSocket->Wait(ESocketWaitConditions::WaitForWrite, FTimespan::FromMilliseconds(10));
			continue;
		}

		OD_LOG(Warning, TEXT("UProtocolSocketBase::SendToConnected failed: sent=%d/%d, bytesSent=%d, err=%d, retry=%d"),
			Offset, TotalBytes, BytesSent, static_cast<int32>(LastSocketError), RetryCount);
		return;
	}
}


bool UProtocolSocketBase::FormatIP4ToNumber(const FString& IpAddress, uint8(&Out)[4])
{
	const FString OriginalIpAddress = IpAddress;
	auto _ip = IpAddress.ToLower();
	if (_ip == TEXT("localhost") || _ip == TEXT("::1") || _ip == TEXT("[::1]") || _ip == TEXT("0:0:0:0:0:0:0:1"))
	{
		Out[0] = 127;
		Out[1] = 0;
		Out[2] = 0;
		Out[3] = 1;
		return true;
	}

	_ip = _ip.Replace(TEXT(" "), TEXT(""));

	const TCHAR* Delims[] = { TEXT(".") };
	TArray<FString> Parts;
	_ip.ParseIntoArray(Parts, Delims, true);
	if (Parts.Num() != 4)
	{
		OD_LOG(Warning, TEXT("FormatIP4ToNumber failed: original='%s', normalized='%s', parts=%d"), *OriginalIpAddress, *_ip, Parts.Num());
		return false;
	}

	for (int32 i = 0; i < 4; ++i)
	{
		Out[i] = FCString::Atoi(*Parts[i]);
	}

	return true;
}

TTuple<bool, FIPv4Endpoint> UProtocolSocketBase::GetIP4EndPoint(const FString& IpAddress, int32 Port)
{
	uint8 IP4Nums[4];
	if (!FormatIP4ToNumber(IpAddress, IP4Nums))
	{
		OD_LOG(Error, TEXT("UProtocolTcpIpSocket::ipaddress format violation: '%s'"), *IpAddress);
		return MakeTuple(false, FIPv4Endpoint());
	}

	FIPv4Endpoint Endpoint(FIPv4Address(IP4Nums[0], IP4Nums[1], IP4Nums[2], IP4Nums[3]), Port);

	return MakeTuple(true, Endpoint);
}
