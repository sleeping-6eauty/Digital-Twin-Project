#include "ProductionSubsystem.h"
#include "WebSocketsModule.h"
#include "IWebSocket.h"
#include "Json.h"

void UProductionSubsystem::Initialize(FSubsystemCollectionBase& Collection)
{
    Super::Initialize(Collection);
    FTimerHandle Handle;
    GetGameInstance()->GetTimerManager().SetTimer(Handle, [this]()
    {
        Connect();
    }, 0.5f, false);
}

void UProductionSubsystem::Deinitialize()
{
    if (WebSocket.IsValid() && WebSocket->IsConnected())
        WebSocket->Close();
    Super::Deinitialize();
}

void UProductionSubsystem::Connect()
{
    FString WsUrl = BackendUrl.Replace(TEXT("http://"), TEXT("ws://"))
                              .Replace(TEXT("https://"), TEXT("wss://"))
                    + TEXT("/ws/ue5");

    WebSocket = FWebSocketsModule::Get().CreateWebSocket(WsUrl, TEXT("ws"));
    WebSocket->OnMessage().AddUObject(this, &UProductionSubsystem::OnMessage);
    WebSocket->OnClosed().AddUObject(this, &UProductionSubsystem::OnClosed);
    WebSocket->OnConnectionError().AddUObject(this, &UProductionSubsystem::OnError);
    WebSocket->OnConnected().AddLambda([this]()
    {
        UE_LOG(LogTemp, Log, TEXT("[Production] connected"));
        OnConnectionChanged.Broadcast(true, TEXT("connected"));
    });
    WebSocket->Connect();
}

FOEEData UProductionSubsystem::ParseOEEObject(const TSharedPtr<FJsonObject>& Obj)
{
    FOEEData Data;
    if (!Obj.IsValid()) return Data;
    Data.Availability = (float)Obj->GetNumberField(TEXT("availability"));
    Data.Performance  = (float)Obj->GetNumberField(TEXT("performance"));
    Data.Quality      = (float)Obj->GetNumberField(TEXT("quality"));
    Data.OEE          = (float)Obj->GetNumberField(TEXT("oee"));
    return Data;
}

void UProductionSubsystem::OnMessage(const FString& Message)
{
    TSharedPtr<FJsonObject> Root;
    TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Message);
    if (!FJsonSerializer::Deserialize(Reader, Root)) return;

    FString Event = Root->GetStringField(TEXT("event"));

    if (Event == TEXT("oee_update"))
    {
        FStationOEEEvent Evt;
        Root->TryGetStringField(TEXT("station_id"), Evt.StationId);
        Root->TryGetStringField(TEXT("body_id"), Evt.BodyId);
        Root->TryGetStringField(TEXT("timestamp"), Evt.Timestamp);
        double CycleTime = 0.0;
        Root->TryGetNumberField(TEXT("cycle_time_sec"), CycleTime);
        Evt.CycleTimeSec = (float)CycleTime;
        const TSharedPtr<FJsonObject>* OeeObj;
        if (Root->TryGetObjectField(TEXT("oee"), OeeObj))
            Evt.OEE = ParseOEEObject(*OeeObj);
        UE_LOG(LogTemp, Log, TEXT("[OEE] station=%s avail=%.3f perf=%.3f qual=%.3f oee=%.3f"),
            *Evt.StationId, Evt.OEE.Availability, Evt.OEE.Performance, Evt.OEE.Quality, Evt.OEE.OEE);
        OnStationOEEUpdated.Broadcast(Evt);
    }
    else if (Event == TEXT("body_completed"))
    {
        FBodyCompletedEvent Evt;
        Root->TryGetStringField(TEXT("station_id"), Evt.StationId);
        Root->TryGetStringField(TEXT("body_id"), Evt.BodyId);
        Root->TryGetStringField(TEXT("timestamp"), Evt.Timestamp);
        double CycleTime = 0.0;
        Root->TryGetNumberField(TEXT("cycle_time_sec"), CycleTime);
        Evt.CycleTimeSec = (float)CycleTime;
        double TotalBodies = 0.0;
        Root->TryGetNumberField(TEXT("total_bodies_completed"), TotalBodies);
        Evt.TotalBodiesCompleted = (int32)TotalBodies;
        const TSharedPtr<FJsonObject>* OeeObj;
        if (Root->TryGetObjectField(TEXT("oee"), OeeObj))
            Evt.OEE = ParseOEEObject(*OeeObj);
        const TSharedPtr<FJsonObject>* LineOeeObj;
        if (Root->TryGetObjectField(TEXT("line_oee"), LineOeeObj))
            Evt.LineOEE = ParseOEEObject(*LineOeeObj);
        UE_LOG(LogTemp, Log, TEXT("[LineOEE] body=%s avail=%.3f perf=%.3f qual=%.3f oee=%.3f total=%d"),
            *Evt.BodyId, Evt.LineOEE.Availability, Evt.LineOEE.Performance, Evt.LineOEE.Quality, Evt.LineOEE.OEE, Evt.TotalBodiesCompleted);
        OnBodyCompleted.Broadcast(Evt);
    }
    else if (Event == TEXT("vision_summary"))
    {
        FVisionSummaryEvent Evt;
        Root->TryGetStringField(TEXT("body_id"), Evt.BodyId);
        Root->TryGetStringField(TEXT("timestamp"), Evt.Timestamp);
        Root->TryGetStringField(TEXT("vision_result"), Evt.VisionResult);
        Root->TryGetStringField(TEXT("defect_type"), Evt.DefectType);
        double TotalInsp = 0, PassCnt = 0, FailCnt = 0, PassRate = 0;
        Root->TryGetNumberField(TEXT("total_inspections"), TotalInsp);
        Root->TryGetNumberField(TEXT("pass_count"), PassCnt);
        Root->TryGetNumberField(TEXT("fail_count"), FailCnt);
        Root->TryGetNumberField(TEXT("pass_rate"), PassRate);
        Evt.TotalInspections = (int32)TotalInsp;
        Evt.PassCount = (int32)PassCnt;
        Evt.FailCount = (int32)FailCnt;
        Evt.PassRate = (float)PassRate;
        UE_LOG(LogTemp, Log, TEXT("[Vision] body=%s result=%s defect=%s total=%d pass=%d fail=%d rate=%.3f"),
            *Evt.BodyId, *Evt.VisionResult, *Evt.DefectType, Evt.TotalInspections, Evt.PassCount, Evt.FailCount, Evt.PassRate);
        OnVisionSummaryUpdated.Broadcast(Evt);
    }
}

void UProductionSubsystem::OnClosed(int32 Code, const FString& Reason, bool bWasClean)
{
    UE_LOG(LogTemp, Warning, TEXT("[Production] disconnected: %s"), *Reason);
    OnConnectionChanged.Broadcast(false, Reason);

    FTimerHandle Handle;
    GetGameInstance()->GetTimerManager().SetTimer(Handle, [this]()
    {
        if (!WebSocket.IsValid() || !WebSocket->IsConnected())
            Connect();
    }, 3.f, false);
}

void UProductionSubsystem::OnError(const FString& Error)
{
    UE_LOG(LogTemp, Error, TEXT("[Production] error: %s"), *Error);
    OnConnectionChanged.Broadcast(false, Error);
}
