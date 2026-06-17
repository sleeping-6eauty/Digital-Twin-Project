// Copyright 2019 ayumax. All Rights Reserved.
#include "Utils/ObjectDelivererLogger.h"

namespace
{
	EODLogVerbosity ToODLogVerbosity(ELogVerbosity::Type Verbosity)
	{
		switch (Verbosity)
		{
		case ELogVerbosity::Fatal:
			return EODLogVerbosity::Fatal;
		case ELogVerbosity::Error:
			return EODLogVerbosity::Error;
		case ELogVerbosity::Warning:
			return EODLogVerbosity::Warning;
		case ELogVerbosity::Display:
			return EODLogVerbosity::Display;
		case ELogVerbosity::Verbose:
			return EODLogVerbosity::Verbose;
		case ELogVerbosity::VeryVerbose:
			return EODLogVerbosity::VeryVerbose;
		case ELogVerbosity::Log:
		default:
			return EODLogVerbosity::Log;
		}
	}
}

void UObjectDelivererLogger::HandleLogMessage(const FString& Message, ELogVerbosity::Type Verbosity, const FName& Category)
{
	OnLogMessage.Broadcast(Message, ToODLogVerbosity(Verbosity), Category);
}
