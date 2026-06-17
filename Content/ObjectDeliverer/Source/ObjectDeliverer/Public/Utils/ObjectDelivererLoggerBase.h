// Copyright 2019 ayumax. All Rights Reserved.
#pragma once

#include "CoreMinimal.h"
#include "ObjectDelivererLoggerBase.generated.h"

UCLASS(Abstract, BlueprintType)
class OBJECTDELIVERER_API UObjectDelivererLoggerBase : public UObject
{
	GENERATED_BODY()

public:
	virtual void HandleLogMessage(const FString& Message, ELogVerbosity::Type Verbosity, const FName& Category) PURE_VIRTUAL(UObjectDelivererLoggerBase::HandleLogMessage, );
};
