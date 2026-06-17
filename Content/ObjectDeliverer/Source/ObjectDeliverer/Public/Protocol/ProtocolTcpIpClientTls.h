// Copyright 2019 ayumax. All Rights Reserved.
#pragma once

#include "CoreMinimal.h"
#include "ProtocolTcpIpSocketTls.h"
#include "ProtocolTcpIpClientTls.generated.h"

UCLASS(BlueprintType, Blueprintable)
class OBJECTDELIVERER_API UProtocolTcpIpClientTls : public UProtocolTcpIpSocketTls
{
	GENERATED_BODY()

public:
	UProtocolTcpIpClientTls();
	~UProtocolTcpIpClientTls();

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	void InitializeTls(const FString& IpAddress = "localhost",
						int32 Port = 8443,
						bool Retry = false,
						bool bAutoConnectAfterDisconnect = false,
						EObjectDelivererTlsProtocol MinimumProtocol = EObjectDelivererTlsProtocol::TLSv1_2);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpClientTls* WithPinnedPublicKey(const FString& PublicKeyDigest);
	
	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpClientTls* WithPinnedPublicKeyFromFile(const FString& PublicKeyHashFilePath);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpClientTls* WithClientCertificate(const FString& CertPath, const FString& KeyPath);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpClientTls* WithCertificateVerification();

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpClientTls* WithTrustedCaCertificate(const FString& CaCertificatePath);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpClientTls* WithPeerVerificationDisabled();

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpClientTls* WithAllowSelfSignedCertificates(bool bAllowSelfSignedCertificates = true);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpClientTls* WithReceiveBufferSize(int32 SizeInBytes);

	UFUNCTION(BlueprintCallable, Category = "ObjectDeliverer|Protocol")
	UProtocolTcpIpClientTls* WithSendBufferSize(int32 SizeInBytes);

	virtual void Start() override;
	virtual void Close() override;

protected:
	virtual bool TryConnect();
	void CreateSocket();
	void OnConnected(FSocket* ConnectionSocket);
	void StopConnectThread();

	virtual void DispatchDisconnected(const UObjectDelivererProtocol* DisconnectedObject) override;

public:
	UPROPERTY(BlueprintReadWrite, EditAnywhere, meta = (ExposeOnSpawn = true), Category = "ObjectDeliverer|Protocol")
	FString ServerIpAddress = "localhost";

	UPROPERTY(BlueprintReadWrite, EditAnywhere, meta = (ExposeOnSpawn = true), Category = "ObjectDeliverer|Protocol")
	int32 ServerPort = 8443;

	UPROPERTY(BlueprintReadWrite, EditAnywhere, meta = (ExposeOnSpawn = true), Category = "ObjectDeliverer|Protocol")
	bool RetryConnect = false;

	UPROPERTY(BlueprintReadWrite, EditAnywhere, meta = (ExposeOnSpawn = true), Category = "ObjectDeliverer|Protocol")
	bool AutoConnectAfterDisconnect = false;

protected:
	class FODWorkerThread* ConnectInnerThread = nullptr;
	class FRunnableThread* ConnectThread = nullptr;

	FIPv4Endpoint ConnectEndPoint;

private:
	FString PinnedPublicKeyDigest;
	bool bPinnedPublicKeyRequested = false;
	FString OriginalServerIdentity = "localhost";
	bool bVerifyPeer = true;
	bool bAllowSelfSigned = false;
	FString TrustedCaCertificatePath;
	FString ClientCertificatePath;
	FString ClientPrivateKeyPath;
	EObjectDelivererTlsProtocol MinimumTlsProtocol = EObjectDelivererTlsProtocol::TLSv1_2;
	TAtomic<bool> IsClosing{false};
};
