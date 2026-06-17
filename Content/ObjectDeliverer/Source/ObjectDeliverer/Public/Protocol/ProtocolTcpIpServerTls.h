// Copyright 2019 ayumax. All Rights Reserved.
#pragma once

#include "CoreMinimal.h"
#include "Sockets.h"
#include "ObjectDelivererProtocol.h"
#include "OpenSSL/OpenSslConnection.h"
#include "ProtocolTcpIpServerTls.generated.h"

class UProtocolTcpIpSocketTls;

UENUM(BlueprintType)
enum class EObjectDelivererClientAuthMode : uint8
{
	None UMETA(DisplayName = "None"),
	Optional UMETA(DisplayName = "Optional"),
	Required UMETA(DisplayName = "Required"),
};

UCLASS(BlueprintType, Blueprintable)
class OBJECTDELIVERER_API UProtocolTcpIpServerTls : public UObjectDelivererProtocol
{
	GENERATED_BODY()

public:
	UProtocolTcpIpServerTls();
	~UProtocolTcpIpServerTls();

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	void InitializeTls(int32 Port,
						const FString& CertPath,
						const FString& KeyPath,
						EObjectDelivererTlsProtocol MinimumProtocol = EObjectDelivererTlsProtocol::TLSv1_2);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpServerTls* WithReceiveBufferSize(int32 SizeInBytes);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpServerTls* WithSendBufferSize(int32 SizeInBytes);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpServerTls* WithClientAuthMode(EObjectDelivererClientAuthMode Mode);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpServerTls* WithClientCaBundle(const FString& CaBundlePath);

	virtual void Start() override;
	virtual void Close() override;
	virtual void Send(const TArray<uint8>& DataBuffer, const FDeliveryDataType& KindOfData) const override;

protected:
	bool OnListen();

	UFUNCTION()
	void DisconnectedClient(const UObjectDelivererProtocol* ClientSocket);

	UFUNCTION()
	void ReceiveDataFromClient(const UObjectDelivererProtocol* ClientSocket, const TArray<uint8>& Buffer);

public:
	UPROPERTY(BlueprintReadWrite, EditAnywhere, meta = (ExposeOnSpawn = true), Category = "ObjectDeliverer|Protocol")
	int32 ListenPort = 8443;

	UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "ObjectDeliverer|Protocol")
	int32 MaxBacklog = 10;

	UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "ObjectDeliverer|Protocol")
	int32 ReceiveBufferSize = 1024 * 1024;

	UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "ObjectDeliverer|Protocol")
	int32 SendBufferSize = 1024 * 1024;

	UPROPERTY(BlueprintReadOnly, EditAnywhere, meta = (ExposeOnSpawn = true), Category = "ObjectDeliverer|Protocol")
	FString CertificatePath = "";

	UPROPERTY(BlueprintReadOnly, EditAnywhere, meta = (ExposeOnSpawn = true), Category = "ObjectDeliverer|Protocol")
	FString KeyPath = "";

	UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "ObjectDeliverer|Protocol")
	EObjectDelivererTlsProtocol MinimumTlsProtocol = EObjectDelivererTlsProtocol::TLSv1_2;

	UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "ObjectDeliverer|Protocol")
	EObjectDelivererClientAuthMode ClientAuthMode = EObjectDelivererClientAuthMode::None;

	UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "ObjectDeliverer|Protocol")
	FString ClientCaBundlePath = "";

protected:
	FSocket* ListenerSocket = nullptr;
	class FODWorkerThread* ListenInnerThread = nullptr;
	class FRunnableThread* ListenThread = nullptr;

	UPROPERTY()
	TArray<UProtocolTcpIpSocketTls*> ConnectedSockets;
	mutable FCriticalSection ConnectedSocketsCriticalSection;

	TAtomic<bool> IsClosing{false};
};
