/* Copyright 2023 Le V??ng Gia Huan */

#include "Utils/ODLog.h"
#include "Utils/ObjectDelivererLoggerBase.h"
#include "Async/Async.h"
#include "Misc/ScopeLock.h"

OBJECTDELIVERER_API DEFINE_LOG_CATEGORY(ODLog);

namespace
{
	TAtomic<UObjectDelivererLoggerBase*> GObjectDelivererLoggerRaw(nullptr);
	TWeakObjectPtr<UObjectDelivererLoggerBase> GObjectDelivererLoggerWeak;
	FCriticalSection GObjectDelivererLoggerMutex;

	void ResetLoggerUnsafe()
	{
		GObjectDelivererLoggerWeak.Reset();
		GObjectDelivererLoggerRaw.Store(nullptr);
	}
}

void ObjectDelivererLog::SetLogger(UObjectDelivererLoggerBase* InLogger)
{
	FScopeLock lock(&GObjectDelivererLoggerMutex);
	GObjectDelivererLoggerWeak = InLogger;
	GObjectDelivererLoggerRaw.Store(InLogger);
}

void ObjectDelivererLog::ClearLogger()
{
	FScopeLock lock(&GObjectDelivererLoggerMutex);
	ResetLoggerUnsafe();
}

bool ObjectDelivererLog::HasLogger()
{
	return GObjectDelivererLoggerRaw.Load() != nullptr;
}

void ObjectDelivererLog::NotifyLogger(const FString& Message, ELogVerbosity::Type Verbosity, const FName& Category)
{
	if (!HasLogger())
	{
		return;
	}

	UObjectDelivererLoggerBase* LoggerSnapshot = nullptr;
	{
		FScopeLock lock(&GObjectDelivererLoggerMutex);
		LoggerSnapshot = GObjectDelivererLoggerWeak.Get();
		if (!LoggerSnapshot)
		{
			ResetLoggerUnsafe();
			return;
		}
	}

	TWeakObjectPtr<UObjectDelivererLoggerBase> WeakLogger(LoggerSnapshot);
	if (IsInGameThread())
	{
		if (auto* LoggerPtr = WeakLogger.Get())
		{
			LoggerPtr->HandleLogMessage(Message, Verbosity, Category);
		}
		return;
	}

	AsyncTask(ENamedThreads::GameThread, [WeakLogger, Message, Verbosity, Category]()
	{
		if (auto* LoggerPtr = WeakLogger.Get())
		{
			LoggerPtr->HandleLogMessage(Message, Verbosity, Category);
		}
	});
}
