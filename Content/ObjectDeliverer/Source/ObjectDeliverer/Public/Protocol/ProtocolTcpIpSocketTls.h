// Copyright 2019 ayumax. All Rights Reserved.
#pragma once

#include "CoreMinimal.h"
#include "ProtocolTcpIpSocket.h"
#include "OpenSSL/OpenSslConnection.h"
#include <atomic>
#include "ProtocolTcpIpSocketTls.generated.h"

UCLASS(BlueprintType, Blueprintable)
class OBJECTDELIVERER_API UProtocolTcpIpSocketTls : public UProtocolTcpIpSocket
{
	GENERATED_BODY()

 public:
	UProtocolTcpIpSocketTls();
	virtual ~UProtocolTcpIpSocketTls();

	void SetSslConnection(TSharedPtr<FOpenSslConnection> InSslConnection);

	virtual void Close() override;
	virtual void Send(const TArray<uint8>& DataBuffer, const FDeliveryDataType& KindOfData) const override;
	virtual void RequestSend(const TArray<uint8>& DataBuffer, const FDeliveryDataType& DataType) override;
	void OnConnectedWithSsl(FSocket* ConnectionSocket, TSharedPtr<FOpenSslConnection> InSslConnection);
	void OnSSLDataReceived(const uint8* Data, int32 Size);  // Callback from SSL worker thread
	void OnSslDisconnected();  // Callback from SSL worker thread

  protected:
	virtual bool ReceivedData() override;

	TSharedPtr<FOpenSslConnection> SslConnection;
	mutable FCriticalSection SslConnectionCriticalSection;
	// Atomic flag to track if Close() has been initiated - prevents deadlock
	// between Close() and OnSslDisconnected() from SSL worker thread
	std::atomic<bool> bIsSslClosing{false};
};
