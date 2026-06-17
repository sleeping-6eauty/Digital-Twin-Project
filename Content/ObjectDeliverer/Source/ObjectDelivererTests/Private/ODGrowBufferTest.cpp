// Copyright 2019 ayumax. All Rights Reserved.

#include "Misc/AutomationTest.h"
#include "Utils/ODGrowBuffer.h"

IMPLEMENT_SIMPLE_AUTOMATION_TEST(ODGrowBuffer_Tests, "ObjectDeliverer.GrowBuffer.Test", EAutomationTestFlags_ApplicationContextMask | EAutomationTestFlags::SmokeFilter)

bool ODGrowBuffer_Tests::RunTest(const FString& Parameters)
{
	const int packetSize = 1024;

	{
		// Constructor reserves capacity but logical size starts at 0
		auto buffer = ODGrowBuffer(100);

		TestEqual(TEXT("check buffer size (logical)"), buffer.GetLength(), 0);
		TestEqual(TEXT("check inner buffer size (capacity)"), buffer.GetInnerBufferSize(), 100);

		// SetLength sets logical size
		buffer.SetLength(2000);

		TestEqual(TEXT("check buffer size after SetLength"), buffer.GetLength(), 2000);
		TestEqual(TEXT("check inner buffer size after grow"), buffer.GetInnerBufferSize(), packetSize * 2);

		// Add appends data to the end of logical buffer
		uint8 testDataArray[] = { 1, 2, 3 };
		buffer.Add(ODByteSpan(testDataArray, sizeof(testDataArray)));

		TestEqual(TEXT("check buffer size after Add"), buffer.GetLength(), 2003);
		TestEqual(TEXT("check inner buffer size unchanged"), buffer.GetInnerBufferSize(), packetSize * 2);
		TestEqual(TEXT("check Add Data1"), buffer[2000], 1);
		TestEqual(TEXT("check Add Data2"), buffer[2001], 2);
		TestEqual(TEXT("check Add Data3"), buffer[2002], 3);

		// RemoveRangeFromStart shifts data and reduces logical size
		buffer.RemoveRangeFromStart(0, 2000);
		TestEqual(TEXT("check buffer size after Remove"), buffer.GetLength(), 3);
		TestEqual(TEXT("check inner buffer size unchanged"), buffer.GetInnerBufferSize(), packetSize * 2);
		TestEqual(TEXT("check shifted Data1"), buffer[0], 1);
		TestEqual(TEXT("check shifted Data2"), buffer[1], 2);
		TestEqual(TEXT("check shifted Data3"), buffer[2], 3);

		// CopyFrom overwrites data at specified offset
		uint8 testDataArray2[] = { 0xEE, 0xEF };
		buffer.CopyFrom(ODByteSpan(testDataArray2, sizeof(testDataArray2)), 1);
		TestEqual(TEXT("check buffer size after CopyFrom"), buffer.GetLength(), 3);
		TestEqual(TEXT("check inner buffer size unchanged"), buffer.GetInnerBufferSize(), packetSize * 2);
		TestEqual(TEXT("check Data1 unchanged"), buffer[0], 1);
		TestEqual(TEXT("check Data2 overwritten"), buffer[1], 0xEE);
		TestEqual(TEXT("check Data3 overwritten"), buffer[2], 0xEF);

		// Clear resets logical size to 0
		buffer.Clear();
		TestEqual(TEXT("check buffer size after Clear"), buffer.GetLength(), 0);
		TestEqual(TEXT("check inner buffer size preserved"), buffer.GetInnerBufferSize(), packetSize * 2);
	}

	return true;
}

