// Copyright 2019 ayumax. All Rights Reserved.
#include "ODWorkerThread.h"
#include "HAL/PlatformProcess.h"

FODWorkerThread::FODWorkerThread(TFunction<bool()> InWork, float WaitSeconds)
	: Work(InWork)
	, End([]() {})
	, Seconds(WaitSeconds)
	, ContinueRun(true)
{

}

FODWorkerThread::FODWorkerThread(TFunction<bool()> InWork, TFunction<void()> InEnd, float WaitSeconds)
	: Work(InWork)
	, End(InEnd)
	, Seconds(WaitSeconds)
	, ContinueRun(true)
{

}

FODWorkerThread::~FODWorkerThread()
{

}

uint32 FODWorkerThread::Run()
{
	while (ContinueRun.Load())
	{
		if (!Work())
		{
			return 0;
		}


		if (ContinueRun.Load())
		{
			FPlatformProcess::Sleep(Seconds);
		}
	}

	return 0;
}

void FODWorkerThread::Stop()
{
	ContinueRun.Store(false);

}

void FODWorkerThread::Exit()
{
	ContinueRun.Store(false);

	End();
}
