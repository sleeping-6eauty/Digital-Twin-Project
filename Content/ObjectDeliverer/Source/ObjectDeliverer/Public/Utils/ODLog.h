/* Copyright 2023 Le V??ng Gia Huan */

#pragma once
#include "CoreMinimal.h"

class UObjectDelivererLoggerBase;

OBJECTDELIVERER_API DECLARE_LOG_CATEGORY_EXTERN(ODLog, Log, All);

namespace ObjectDelivererLog
{
	OBJECTDELIVERER_API void SetLogger(UObjectDelivererLoggerBase* InLogger);
	OBJECTDELIVERER_API void ClearLogger();
	OBJECTDELIVERER_API bool HasLogger();
	OBJECTDELIVERER_API void NotifyLogger(const FString& Message, ELogVerbosity::Type Verbosity, const FName& Category);
}

#define OD_LOG(Verbosity, Format, ...) \
	do \
	{ \
		if (ObjectDelivererLog::HasLogger()) \
		{ \
			const FString __od_message = FString::Printf(Format, ##__VA_ARGS__); \
			ObjectDelivererLog::NotifyLogger(__od_message, ELogVerbosity::Verbosity, FName(TEXT("ODLog"))); \
			if (UE_LOG_ACTIVE(ODLog, Verbosity)) \
			{ \
				UE_LOG(ODLog, Verbosity, TEXT("%s"), *__od_message); \
			} \
		} \
		else \
		{ \
			UE_LOG(ODLog, Verbosity, Format, ##__VA_ARGS__); \
		} \
	} while (0)
