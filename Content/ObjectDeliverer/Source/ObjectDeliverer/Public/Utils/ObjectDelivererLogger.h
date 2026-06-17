// Copyright 2019 ayumax. All Rights Reserved.
#pragma once

#include "CoreMinimal.h"
#include "Utils/ObjectDelivererLoggerBase.h"
#include "ObjectDelivererLogger.generated.h"

UENUM(BlueprintType)
enum class EODLogVerbosity : uint8
{
	Fatal UMETA(DisplayName = "Fatal"),
	Error UMETA(DisplayName = "Error"),
	Warning UMETA(DisplayName = "Warning"),
	Display UMETA(DisplayName = "Display"),
	Log UMETA(DisplayName = "Log"),
	Verbose UMETA(DisplayName = "Verbose"),
	VeryVerbose UMETA(DisplayName = "VeryVerbose"),
};

DECLARE_DYNAMIC_MULTICAST_DELEGATE_ThreeParams(FObjectDelivererLogMessageEvent, const FString&, Message, EODLogVerbosity, Verbosity, FName, Category);

UCLASS(BlueprintType, Blueprintable)
class OBJECTDELIVERER_API UObjectDelivererLogger : public UObjectDelivererLoggerBase
{
	GENERATED_BODY()

public:
	/**
	 * Called when ODLog is emitted.
	 */
	UPROPERTY(BlueprintAssignable, Category = "ObjectDeliverer|Logging")
	FObjectDelivererLogMessageEvent OnLogMessage;

	virtual void HandleLogMessage(const FString& Message, ELogVerbosity::Type Verbosity, const FName& Category) override;
};
