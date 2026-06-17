// Copyright 2019 ayumax. All Rights Reserved.
#include "PacketRule/PacketRuleSizeBody.h"
#include "PacketRule/PacketRuleFactory.h"
#include "Utils/ODLog.h"
#include <atomic>

namespace
{
	std::atomic<int32> GMakeSendPacketDebugCounter{0};
	std::atomic<int32> GNotifyReceiveDataDebugCounter{0};
	std::atomic<int32> GOnReceivedSizeDebugCounter{0};
	std::atomic<int32> GOnReceivedBodyDebugCounter{0};
}

UPacketRuleSizeBody::UPacketRuleSizeBody()
{

}

UPacketRuleSizeBody::~UPacketRuleSizeBody()
{
}

void UPacketRuleSizeBody::Initialize()
{
	BufferForSend.SetNum(1024);
	ReceiveMode = EReceiveMode::Size;
	BodySize = 0;
}

void UPacketRuleSizeBody::MakeSendPacket(const TArray<uint8>& BodyBuffer, const FDeliveryDataType& DataType)
{
	const auto BodyBufferNum{ BodyBuffer.Num() };
	BufferForSend.SetNum(BodyBufferNum + SizeLength, EAllowShrinking::No);

	for (decltype(SizeLength) i{ 0u }; i < SizeLength; i++)
		if (BufferForSend.IsValidIndex(i))
			BufferForSend[i] = (BodyBufferNum >> (SizeBufferEndian == ECNBufferEndian::Big ? 8 * (SizeLength - i - 1) : 8 * i)) & 0xFF;

	FMemory::Memcpy(BufferForSend.GetData() + SizeLength, BodyBuffer.GetData(), BodyBufferNum);

	const int32 CallCount = GMakeSendPacketDebugCounter.fetch_add(1, std::memory_order_relaxed) + 1;
	if (CallCount <= 10 || CallCount % 100 == 0)
	{
		OD_LOG(Log, TEXT("PacketRuleSizeBody::MakeSendPacket: BodyNum=%d, BufferForSend.Num()=%d, first 5 bytes=[%d,%d,%d,%d,%d] (call #%d)"),
			BodyBufferNum, BufferForSend.Num(),
			BufferForSend.Num() > 0 ? BufferForSend[0] : -1,
			BufferForSend.Num() > 1 ? BufferForSend[1] : -1,
			BufferForSend.Num() > 2 ? BufferForSend[2] : -1,
			BufferForSend.Num() > 3 ? BufferForSend[3] : -1,
			BufferForSend.Num() > 4 ? BufferForSend[4] : -1,
			CallCount);
	}
	
	DispatchMadeSendBuffer(BufferForSend, DataType);
}

void UPacketRuleSizeBody::NotifyReceiveData(const TArray<uint8>& DataBuffer)
{
	const int32 CallCount = GNotifyReceiveDataDebugCounter.fetch_add(1, std::memory_order_relaxed) + 1;
	if (CallCount <= 20 || CallCount % 100 == 0)
	{
		OD_LOG(Log, TEXT("PacketRuleSizeBody::NotifyReceiveData: Mode=%s, BufferSize=%d, FirstByte=%d (call #%d)"),
			ReceiveMode == EReceiveMode::Size ? TEXT("Size") : TEXT("Body"),
			DataBuffer.Num(),
			DataBuffer.Num() > 0 ? DataBuffer[0] : -1,
			CallCount);
	}
	
	if (ReceiveMode == EReceiveMode::Size)
	{
		OnReceivedSize(DataBuffer);
		return;
	}

	OnReceivedBody(DataBuffer);
}

void UPacketRuleSizeBody::OnReceivedSize(const TArray<uint8>& DataBuffer)
{
	BodySize = 0;
	for (int i = 0; i < SizeLength; ++i)
	{
		int32 offset = 0;
		if (SizeBufferEndian == ECNBufferEndian::Big)
		{
			offset = 8 * (SizeLength - i - 1);
		}
		else
		{
			offset = 8 * i;
		}
		BodySize |= (DataBuffer[i] << offset);
	}

	const int32 CallCount = GOnReceivedSizeDebugCounter.fetch_add(1, std::memory_order_relaxed) + 1;
	if (CallCount <= 20 || CallCount % 100 == 0)
	{
		OD_LOG(Log, TEXT("PacketRuleSizeBody::OnReceivedSize: BodySize=%d (call #%d)"), BodySize, CallCount);
	}

	ReceiveMode = EReceiveMode::Body;
}

void UPacketRuleSizeBody::OnReceivedBody(const TArray<uint8>& DataBuffer)
{
	const int32 CallCount = GOnReceivedBodyDebugCounter.fetch_add(1, std::memory_order_relaxed) + 1;
	if (CallCount <= 20 || CallCount % 100 == 0)
	{
		OD_LOG(Log, TEXT("PacketRuleSizeBody::OnReceivedBody: BufferSize=%d, FirstByte=%d (call #%d)"),
			DataBuffer.Num(),
			DataBuffer.Num() > 0 ? DataBuffer[0] : -1,
			CallCount);
	}

	DispatchMadeReceiveBuffer(DataBuffer);

	BodySize = 0;

	ReceiveMode = EReceiveMode::Size;
}

int32 UPacketRuleSizeBody::GetWantSize()
{
	if (ReceiveMode == EReceiveMode::Size)
	{
		return SizeLength;
	}

	return BodySize;
}

UPacketRule* UPacketRuleSizeBody::Clone()
{
	return UPacketRuleFactory::CreatePacketRuleSizeBody(SizeLength, SizeBufferEndian);
}
