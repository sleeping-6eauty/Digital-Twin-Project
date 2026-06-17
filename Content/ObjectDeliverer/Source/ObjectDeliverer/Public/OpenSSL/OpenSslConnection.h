// Copyright 2019 ayumax. All Rights Reserved.
#pragma once

#include "CoreMinimal.h"
#include "Sockets.h"
#include "Containers/Queue.h"
#include "OpenSslConnection.generated.h"

struct ssl_st;
struct ssl_ctx_st;
struct bio_st;

UENUM(BlueprintType)
enum class EObjectDelivererTlsProtocol : uint8
{
	TLSv1_2 UMETA(DisplayName = "TLS 1.2"),
	TLSv1_1 UMETA(DisplayName = "TLS 1.1 (Deprecated)"),
	TLSv1_0 UMETA(DisplayName = "TLS 1.0 (Deprecated)"),
};

enum class EObjectDelivererTlsClientAuthMode : uint8
{
	None,
	Optional,
	Required,
};

// Forward declarations
class FSSLWorkerThread;

class OBJECTDELIVERER_API FOpenSslConnection
{
	// Allow FSSLWorkerThread to access private members
	friend class FSSLWorkerThread;

public:
	FOpenSslConnection();
	~FOpenSslConnection();

	// Minimum TLS protocol version for negotiation (not a fixed/maximum version).
	bool InitializeForClient(EObjectDelivererTlsProtocol MinimumProtocol = EObjectDelivererTlsProtocol::TLSv1_2);
	bool InitializeForServer(const FString& CertPath, const FString& KeyPath, EObjectDelivererTlsProtocol MinimumProtocol = EObjectDelivererTlsProtocol::TLSv1_2);

	bool Connect(FSocket* InSocket, const FString& HostName);
	bool Accept(FSocket* InSocket);

	// Send queues data to be sent by the SSL worker thread
	int32 Send(const uint8* Data, int32 Size);

	// Recv should NOT be called directly - data is received by the worker thread and delivered via callback
	int32 Recv(uint8* Data, int32 Size);

	void Close();
	bool IsConnected() const;
	bool HasError() const;

	void SetVerifyMode(bool bVerifyPeer, bool bAllowSelfSigned);
	bool SetTrustedCaCertificate(const FString& CaCertificatePath);
	bool SetClientCertificate(const FString& CertPath, const FString& KeyPath);
	void SetClientAuthMode(EObjectDelivererTlsClientAuthMode Mode);
	bool SetClientCaCertificate(const FString& CaCertificatePath);
	bool SetPinnedPublicKey(const FString& PublicKeyDigest);

	FString GetLastError() const;

	// Callback for received data (called from worker thread)
	DECLARE_MULTICAST_DELEGATE_TwoParams(FOnDataReceived, const uint8*, int32);
	FOnDataReceived& OnDataReceived() { return DataReceivedDelegate; }

	// Callback for disconnection (called from worker thread)
	DECLARE_MULTICAST_DELEGATE(FOnDisconnected);
	FOnDisconnected& OnDisconnected() { return DisconnectedDelegate; }

	// Start the SSL worker thread - call AFTER registering OnDataReceived callback
	void StartWorkerThread();

private:
	bool CreateSslContext(EObjectDelivererTlsProtocol MinimumProtocol);
	bool LoadCertificateAndKey(const FString& CertPath, const FString& KeyPath);
	bool ApplyServerClientAuthSettings();
	bool SetupSocketBio(FSocket* InSocket);
	void StopSSLWorkerThread();
	void NotifyDisconnected();

private:
	ssl_st* Ssl = nullptr;
	ssl_ctx_st* SslCtx = nullptr;
	bio_st* SocketBio = nullptr;
	FSocket* Socket = nullptr;
	bool bConnected = false;
	bool bIsServer = false;
	bool bVerifyPeer = false;
	bool bAllowSelfSigned = false;
	FString TrustedCaCertificatePath;
	FString ClientCertificatePath;
	FString ClientPrivateKeyPath;
	EObjectDelivererTlsClientAuthMode ClientAuthMode = EObjectDelivererTlsClientAuthMode::None;
	FString ClientCaCertificatePath;
	FString PinnedPublicKeyDigest;
	FString LastError;

	// SSL worker thread - all SSL operations happen here
	FSSLWorkerThread* SSLWorker = nullptr;
	FRunnableThread* WorkerThread = nullptr;

	// Send queue - data to be sent is queued here
	TQueue<TArray<uint8>> SendQueue;
	FCriticalSection SendQueueMutex;

	// Delegate for received data
	FOnDataReceived DataReceivedDelegate;
	FOnDisconnected DisconnectedDelegate;

	std::atomic<bool> bDisconnectedNotified{false};

	// Flag to stop the worker thread
	std::atomic<bool> bStopWorker;
};
