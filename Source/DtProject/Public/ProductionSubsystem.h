#pragma once

#include "CoreMinimal.h"
#include "Subsystems/GameInstanceSubsystem.h"
#include "IWebSocket.h"
#include "ProductionSubsystem.generated.h"

USTRUCT(BlueprintType)
struct FOEEData
{
    GENERATED_BODY()

    UPROPERTY(BlueprintReadOnly) float Availability = 0.f;
    UPROPERTY(BlueprintReadOnly) float Performance = 0.f;
    UPROPERTY(BlueprintReadOnly) float Quality = 0.f;
    UPROPERTY(BlueprintReadOnly) float OEE = 0.f;
};

USTRUCT(BlueprintType)
struct FStationOEEEvent
{
    GENERATED_BODY()

    UPROPERTY(BlueprintReadOnly) FString StationId;
    UPROPERTY(BlueprintReadOnly) FString BodyId;
    UPROPERTY(BlueprintReadOnly) FString Timestamp;
    UPROPERTY(BlueprintReadOnly) FOEEData OEE;
    UPROPERTY(BlueprintReadOnly) float CycleTimeSec = 0.f;
};

USTRUCT(BlueprintType)
struct FBodyCompletedEvent
{
    GENERATED_BODY()

    UPROPERTY(BlueprintReadOnly) FString StationId;
    UPROPERTY(BlueprintReadOnly) FString BodyId;
    UPROPERTY(BlueprintReadOnly) FString Timestamp;
    UPROPERTY(BlueprintReadOnly) FOEEData OEE;
    UPROPERTY(BlueprintReadOnly) float CycleTimeSec = 0.f;
    UPROPERTY(BlueprintReadOnly) FOEEData LineOEE;
    UPROPERTY(BlueprintReadOnly) int32 TotalBodiesCompleted = 0;
};

USTRUCT(BlueprintType)
struct FVisionSummaryEvent
{
    GENERATED_BODY()

    UPROPERTY(BlueprintReadOnly) FString BodyId;
    UPROPERTY(BlueprintReadOnly) FString Timestamp;
    UPROPERTY(BlueprintReadOnly) FString VisionResult;
    UPROPERTY(BlueprintReadOnly) FString DefectType;
    UPROPERTY(BlueprintReadOnly) int32 TotalInspections = 0;
    UPROPERTY(BlueprintReadOnly) int32 PassCount = 0;
    UPROPERTY(BlueprintReadOnly) int32 FailCount = 0;
    UPROPERTY(BlueprintReadOnly) float PassRate = 0.f;
};

DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FOnStationOEEUpdated, const FStationOEEEvent&, Event);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FOnBodyCompleted, const FBodyCompletedEvent&, Event);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FOnVisionSummaryUpdated, const FVisionSummaryEvent&, Event);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(FOnConnectionChanged, bool, bConnected, const FString&, Reason);

UCLASS()
class DTPROJECT_API UProductionSubsystem : public UGameInstanceSubsystem
{
    GENERATED_BODY()

public:
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;

    // 스테이션 OEE 업데이트 수신 시 호출
    UPROPERTY(BlueprintAssignable, Category = "Production")
    FOnStationOEEUpdated OnStationOEEUpdated;

    // 차체 1대 완성 시 호출 (라인 OEE 포함)
    UPROPERTY(BlueprintAssignable, Category = "Production")
    FOnBodyCompleted OnBodyCompleted;

    // 비전 검사 집계 업데이트 수신 시 호출
    UPROPERTY(BlueprintAssignable, Category = "Production")
    FOnVisionSummaryUpdated OnVisionSummaryUpdated;

    UPROPERTY(BlueprintAssignable, Category = "Production")
    FOnConnectionChanged OnConnectionChanged;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Production")
    FString BackendWebSocketUrl = TEXT("ws://127.0.0.1:8000/ws/ue5");

private:
    TSharedPtr<IWebSocket> WebSocket;

    void Connect();
    void OnMessage(const FString& Message);
    void OnClosed(int32 Code, const FString& Reason, bool bWasClean);
    void OnError(const FString& Error);

    static FOEEData ParseOEEObject(const TSharedPtr<FJsonObject>& Obj);
};
