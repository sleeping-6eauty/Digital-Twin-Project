// Copyright 2019 ayumax. All Rights Reserved.
#include "CoreMinimal.h"
#include "Misc/AutomationTest.h"
#include "Tests/AutomationCommon.h"
#include "Protocol/ProtocolTcpIpClientTls.h"
#include "Protocol/ProtocolTcpIpServerTls.h"
#include "PacketRule/PacketRuleFactory.h"
#include "PacketRule/PacketRuleSizeBody.h"
#include "PacketRule/PacketRuleNodivision.h"
#include "PacketRule/PacketRuleFixedLength.h"
#include "PacketRule/PacketRuleTerminate.h"
#include "Protocol/ProtocolFactory.h"
#include "ObjectDelivererManager.h"
#include "ObjectDelivererManagerTestHelper.h"
#include "Utils/ObjectDelivererCertificateGenerator.h"
#include "Misc/CommandLine.h"
#include "Misc/Parse.h"
#include "Misc/Paths.h"
#include "HAL/FileManager.h"
#include "HAL/PlatformMisc.h"
#include "HAL/PlatformFileManager.h"
#include "Sockets.h"
#include "SocketSubsystem.h"
#include "Async/Async.h"
#include "Utils/ODLog.h"
#include <stdlib.h>

#if PLATFORM_UNIX
	#include <sys/stat.h>
#endif

#if WITH_DEV_AUTOMATION_TESTS

namespace
{
	FString NormalizeTlsTestConfigValue(FString Value)
	{
		Value.TrimStartAndEndInline();
		if (Value.Len() >= 2)
		{
			const TCHAR FirstChar = Value[0];
			const TCHAR LastChar = Value[Value.Len() - 1];
			if ((FirstChar == TEXT('"') && LastChar == TEXT('"')) ||
				(FirstChar == TEXT('\'') && LastChar == TEXT('\'')))
			{
				Value = Value.Mid(1, Value.Len() - 2);
			}
		}
		return Value;
	}

	bool IsTruthyEnvValue(const FString& Value)
	{
		return Value.Equals(TEXT("1")) ||
			Value.Equals(TEXT("true"), ESearchCase::IgnoreCase) ||
			Value.Equals(TEXT("yes"), ESearchCase::IgnoreCase) ||
			Value.Equals(TEXT("on"), ESearchCase::IgnoreCase);
	}

	FString GetTlsTestEnvironmentVariable(const TCHAR* Name)
	{
#if PLATFORM_ANDROID || PLATFORM_IOS
		const FTCHARToUTF8 NameUtf8(Name);
		const char* Value = ::getenv(NameUtf8.Get());
		FString Result = Value ? UTF8_TO_TCHAR(Value) : FString();
		if (Result.IsEmpty())
		{
			const FString Match = FString::Printf(TEXT("%s="), Name);
			FParse::Value(FCommandLine::Get(), *Match, Result);
		}
		return NormalizeTlsTestConfigValue(MoveTemp(Result));
#else
		return NormalizeTlsTestConfigValue(FPlatformMisc::GetEnvironmentVariable(Name));
#endif
	}

	void SetTlsTestEnvironmentVariable(const TCHAR* Name, const TCHAR* Value)
	{
#if PLATFORM_ANDROID || PLATFORM_IOS
		const FTCHARToUTF8 NameUtf8(Name);
		const FTCHARToUTF8 ValueUtf8(Value ? Value : TEXT(""));
		if (!Value || Value[0] == TEXT('\0'))
		{
			unsetenv(NameUtf8.Get());
			return;
		}
		setenv(NameUtf8.Get(), ValueUtf8.Get(), 1);
#else
		FPlatformMisc::SetEnvironmentVar(Name, Value);
#endif
	}

	int32 GetTlsTestEnvironmentInt(const TCHAR* Name, const int32 DefaultValue)
	{
		const FString Value = GetTlsTestEnvironmentVariable(Name);
		if (Value.IsEmpty())
		{
			return DefaultValue;
		}

		TCHAR* EndPtr = nullptr;
		const int64 Parsed = FCString::Strtoi64(*Value, &EndPtr, 10);
		if (EndPtr == *Value || (EndPtr && *EndPtr != TEXT('\0')))
		{
			return DefaultValue;
		}

		return static_cast<int32>(Parsed);
	}

	bool IsExternalTlsEchoTestEnabled()
	{
		return IsTruthyEnvValue(GetTlsTestEnvironmentVariable(TEXT("OD_TLS_EXTERNAL_ENABLED")));
	}

	FString GetExternalTlsEchoHost()
	{
		const FString Host = GetTlsTestEnvironmentVariable(TEXT("OD_TLS_EXTERNAL_HOST"));
		return Host.IsEmpty() ? TEXT("ayumaxsoft.online") : Host;
	}

	int32 GetExternalTlsWrongPort()
	{
		return GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_WRONG_PORT"), 9199);
	}

	void ConfigureExternalTlsClient(UProtocolTcpIpClientTls* Client)
	{
		Client->WithCertificateVerification();
		const FString CaPath = GetTlsTestEnvironmentVariable(TEXT("OD_TLS_EXTERNAL_TRUSTED_CA_CERT"));
		if (!CaPath.IsEmpty())
		{
			Client->WithTrustedCaCertificate(CaPath);
		}
	}

	template <typename TObject, typename... TArgs>
	TObject* NewTlsTestObject(TArgs&&... Args)
	{
		TObject* Object = ::NewObject<TObject>(Forward<TArgs>(Args)...);
#if PLATFORM_ANDROID || PLATFORM_IOS
		if (Object)
		{
			Object->AddToRoot();
		}
#endif
		return Object;
	}
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsFactoryTest,
								"ObjectDeliverer.ProtocolTcpIpTls.FactoryTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsFactoryTest::RunTest(const FString &Parameters)
{
	auto client = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), 9443, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	TestNotNull("TLS Client should not be null", client);
	TestTrue("TLS Client should be valid", IsValid(client));

	auto server = UProtocolFactory::CreateProtocolTcpIpServerTls(9443, TEXT(""), TEXT(""), EObjectDelivererTlsProtocol::TLSv1_2);
	TestNotNull("TLS Server should not be null", server);
	TestTrue("TLS Server should be valid", IsValid(server));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsClientWithVerifySettingsTest,
								"ObjectDeliverer.ProtocolTcpIpTls.ClientWithVerifySettingsTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsClientWithVerifySettingsTest::RunTest(const FString &Parameters)
{
	// Test-only placeholder public key digest used for verifying TLS client configuration logic.
	static const TCHAR* TestPinnedPublicKeyDigest = TEXT("aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00");

	auto client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	
	client->WithCertificateVerification();
	client->WithTrustedCaCertificate(TEXT("/tmp/objectdeliverer-test-ca.crt"));
	client->WithAllowSelfSignedCertificates(true);
	client->WithPinnedPublicKey(TestPinnedPublicKeyDigest);

	TestNotNull("TLS Client should not be null", client);
	TestTrue("TLS Client should be valid", IsValid(client));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsServerCertificateGenerationTest,
								"ObjectDeliverer.ProtocolTcpIpTls.ServerCertificateGenerationTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsServerCertificateGenerationTest::RunTest(const FString &Parameters)
{
	FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));

	IFileManager::Get().MakeDirectory(*OutputPath, true);

	bool Success = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(OutputPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Self-signed certificate generation should succeed", Success);

	FString CertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	FString KeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	TestTrue("Certificate file should exist", FPaths::FileExists(CertPath));
	TestTrue("Key file should exist", FPaths::FileExists(KeyPath));

#if PLATFORM_UNIX
	// Verify that the private key file has restrictive permissions (600) on Unix systems
	FString AbsoluteKeyPath = IFileManager::Get().ConvertToAbsolutePathForExternalAppForRead(*KeyPath);
	struct stat KeyStat;
	if (stat(TCHAR_TO_UTF8(*AbsoluteKeyPath), &KeyStat) == 0)
	{
		mode_t KeyPerms = KeyStat.st_mode & 0777;
		TestEqual("Private key file should have 600 permissions", KeyPerms, static_cast<mode_t>(0600));
	}
	else
	{
		AddWarning(FString::Printf(TEXT("Could not stat private key file: %s"), *KeyPath));
	}
#endif

	const bool bCertDeleted = IFileManager::Get().Delete(*CertPath, true, true);
	if (!bCertDeleted)
	{
		OD_LOG(Warning, TEXT("Failed to delete certificate file: %s"), *CertPath);
	}

	const bool bKeyDeleted = IFileManager::Get().Delete(*KeyPath, true, true);
	if (!bKeyDeleted)
	{
		OD_LOG(Warning, TEXT("Failed to delete key file: %s"), *KeyPath);
	}

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsBufferSizeSettingsTest,
								"ObjectDeliverer.ProtocolTcpIpTls.BufferSizeSettingsTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsBufferSizeSettingsTest::RunTest(const FString &Parameters)
{
	auto client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	client->WithReceiveBufferSize(2048);
	client->WithSendBufferSize(4096);
	TestNotNull("TLS Client should not be null", client);

	auto server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	server->WithReceiveBufferSize(4096);
	server->WithSendBufferSize(8192);
	TestNotNull("TLS Server should not be null", server);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsMinimumProtocolVersionTest,
								"ObjectDeliverer.ProtocolTcpIpTls.MinimumProtocolVersionTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsMinimumProtocolVersionTest::RunTest(const FString& Parameters)
{
	auto ClientV1_2 = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), 9443, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	TestNotNull("TLS 1.2 Client should not be null", ClientV1_2);

	auto ClientV1_1 = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), 9444, false, false, EObjectDelivererTlsProtocol::TLSv1_1);
	TestNotNull("TLS 1.1 Client should not be null", ClientV1_1);

	auto ClientV1_0 = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), 9445, false, false, EObjectDelivererTlsProtocol::TLSv1_0);
	TestNotNull("TLS 1.0 Client should not be null", ClientV1_0);

	auto ServerV1_2 = UProtocolFactory::CreateProtocolTcpIpServerTls(9443, TEXT(""), TEXT(""), EObjectDelivererTlsProtocol::TLSv1_2);
	TestNotNull("TLS 1.2 Server should not be null", ServerV1_2);

	return true;
}

/**
 * Helper function to get an available TLS port for testing
 * Returns a unique port number for each call to avoid port conflicts between tests
 * Uses a randomized base port to avoid conflicts with previous test runs
 */
static bool IsAvailableTlsTcpPort(const int32 Port)
{
	ISocketSubsystem* SocketSubsystem = ISocketSubsystem::Get(PLATFORM_SOCKETSUBSYSTEM);
	if (!SocketSubsystem)
	{
		return false;
	}

	FSocket* ProbeSocket = SocketSubsystem->CreateSocket(NAME_Stream, TEXT("ObjectDelivererTlsPortProbe"), false);
	if (!ProbeSocket)
	{
		return false;
	}

	TSharedRef<FInternetAddr> ProbeAddress = SocketSubsystem->CreateInternetAddr();
	ProbeAddress->SetAnyAddress();
	ProbeAddress->SetPort(Port);

	const bool bCanBind = ProbeSocket->Bind(*ProbeAddress);
	ProbeSocket->Close();
	SocketSubsystem->DestroySocket(ProbeSocket);
	return bCanBind;
}

int32 GetAvailableTlsPort()
{
	static constexpr int32 MinTlsTestPort = 20000;
	static constexpr int32 MaxTlsTestPort = 55000;
	static int32 NextCandidatePort = 0;

	if (NextCandidatePort == 0)
	{
		NextCandidatePort = MinTlsTestPort + (FMath::Rand() % (MaxTlsTestPort - MinTlsTestPort + 1));
	}

	constexpr int32 MaxAttempts = MaxTlsTestPort - MinTlsTestPort + 1;
	for (int32 Attempt = 0; Attempt < MaxAttempts; ++Attempt)
	{
		if (NextCandidatePort < MinTlsTestPort || NextCandidatePort > MaxTlsTestPort)
		{
			NextCandidatePort = MinTlsTestPort;
		}

		const int32 CandidatePort = NextCandidatePort++;
		if (IsAvailableTlsTcpPort(CandidatePort))
		{
			return CandidatePort;
		}
	}

	// Fallback: return a deterministic test port if all probing fails.
	return 9443;
}

float GetTlsTestServerStartupDelaySeconds()
{
#if PLATFORM_IOS
	return 0.5f;
#elif PLATFORM_ANDROID
	return 0.25f;
#else
	return 0.1f;
#endif
}

float GetTlsTestClientStartStaggerSeconds()
{
#if PLATFORM_IOS
	return 0.05f;
#elif PLATFORM_ANDROID
	return 0.03f;
#else
	return 0.0f;
#endif
}

float GetTlsTestMultiClientConnectWaitSeconds()
{
#if PLATFORM_IOS || PLATFORM_ANDROID
	return 15.0f;
#else
	return 10.0f;
#endif
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsBasicConnectionTest,
								"ObjectDeliverer.ProtocolTcpIpTls.BasicConnectionTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for basic TLS connection establishment between client and server
 * This test verifies that TLS handshake completes successfully with self-signed certificates
 */
bool FProtocolTcpIpTlsBasicConnectionTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);
	
	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server with generated certificates
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	
	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));

	// Convert to absolute paths to avoid env var resolution issues
	const FString AbsoluteCertDir = FPaths::ConvertRelativePathToFull(CertPath);
	const FString AbsoluteCertPath = FPaths::ConvertRelativePathToFull(ServerCertPath);
	const FString AbsoluteKeyPath = FPaths::ConvertRelativePathToFull(ServerKeyPath);

	// Hint OpenSSL where to find a trust anchor (self-signed) so InitializeSsl succeeds on platforms without system CAs
	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *AbsoluteCertPath);
	}
	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *AbsoluteCertDir);
	}

	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, AbsoluteCertPath, AbsoluteKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Setup client with SSL verification disabled for self-signed cert
	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	
	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait until both sides report a connection to reduce flakiness on slower mobile runners.
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, clientHelper, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (serverHelper->ConnectedSocket.Num() > 0 && clientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual("Server should have one connected client before sending", serverHelper->ConnectedSocket.Num(), 1);
			TestEqual("Client should be connected before sending", clientHelper->ConnectedSocket.Num(), 1);
			return true;
		}

		return false;
	}));

	// Verify TLS connection is established
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, clientHelper]()
	{
		TestEqual("Server should have one connected client", serverHelper->ConnectedSocket.Num(), 1);
		TestEqual("Client should be connected", clientHelper->ConnectedSocket.Num(), 1);
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		ObjectDelivererClient->Close();
		ObjectDelivererServer->Close();
		
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsDataTransferTest,
								"ObjectDeliverer.ProtocolTcpIpTls.DataTransferTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for encrypted data transmission over TLS between client and server
 * This test sends multiple encrypted data packets from client to server and verifies they are correctly received
 */
bool FProtocolTcpIpTlsDataTransferTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);
	
	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server with data receiving capability
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ObjectDelivererServer->ReceiveData.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnReceive);
	
	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));
	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Setup client with SSL verification disabled for self-signed cert
	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	
	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait until both sides report a connection to avoid sending before handshake completion.
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, clientHelper, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (serverHelper->ConnectedSocket.Num() > 0 && clientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual("Server should have one connected client before sending", serverHelper->ConnectedSocket.Num(), 1);
			TestEqual("Client should be connected before sending", clientHelper->ConnectedSocket.Num(), 1);
			return true;
		}

		return false;
	}));

	// Send 100 encrypted data packets from client to server
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ObjectDelivererClient]()
	{
		for (int i = 0; i < 100; ++i)
		{
			uint8 data = i % 256;
			TArray<uint8> sendbuffer = { data };
			ObjectDelivererClient->Send(sendbuffer);
		}
		return true;
	}));

	// Wait for all encrypted data to be received and decrypted
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	// Verify encrypted data was correctly received and decrypted
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper]()
	{
		TestEqual("Server should have received 100 packets", serverHelper->ReceiveBuffers.Num(), 100);
		
		if (serverHelper->ReceiveBuffers.Num() == 100)
		{
			for (int i = 0; i < 100; ++i)
			{
				TArray<uint8>& receivebuf = serverHelper->ReceiveBuffers[i];
				TestTrue("Received packet should not be empty", receivebuf.Num() > 0);
				if (receivebuf.Num() > 0)
				{
					TestEqual("Received data should match sent data", receivebuf[0], static_cast<uint8>(i % 256));
				}
			}
		}
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		ObjectDelivererClient->Close();
		ObjectDelivererServer->Close();
		
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsBidirectionalDataTransferTest,
								"ObjectDeliverer.ProtocolTcpIpTls.BidirectionalDataTransferTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for bidirectional encrypted data transmission over TLS
 * This test sends encrypted data from both client to server and server to client to verify full duplex TLS communication
 */
bool FProtocolTcpIpTlsBidirectionalDataTransferTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);
	
	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server with data receiving capability
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ObjectDelivererServer->ReceiveData.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnReceive);
	
	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));
	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Setup client with data receiving capability
	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ObjectDelivererClient->ReceiveData.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnReceive);
	
	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait for TLS handshake and connection to establish
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	// Send encrypted data from client to server
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ObjectDelivererClient]()
	{
		for (int i = 0; i < 50; ++i)
		{
			uint8 data = i;
			TArray<uint8> sendbuffer = { data };
			ObjectDelivererClient->Send(sendbuffer);
		}
		return true;
	}));

	// Wait for client data to be received
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(10.0f));

	// Send encrypted data from server to client
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ObjectDelivererServer]()
	{
		for (int i = 100; i < 150; ++i)
		{
			uint8 data = i;
			TArray<uint8> sendbuffer = { data };
			ObjectDelivererServer->Send(sendbuffer);
		}
		return true;
	}));

	// Wait for server data to be received
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(10.0f));

	// Verify bidirectional encrypted communication
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, clientHelper]()
	{
		TestEqual("Server should have received 50 packets from client", serverHelper->ReceiveBuffers.Num(), 50);
		TestEqual("Client should have received 50 packets from server", clientHelper->ReceiveBuffers.Num(), 50);
		
		// Verify client to server data
		if (serverHelper->ReceiveBuffers.Num() == 50)
		{
			for (int i = 0; i < 50; ++i)
			{
				TArray<uint8>& receivebuf = serverHelper->ReceiveBuffers[i];
				TestTrue("Server received packet should not be empty", receivebuf.Num() > 0);
				if (receivebuf.Num() > 0)
				{
					TestEqual("Server received data should match", receivebuf[0], static_cast<uint8>(i));
				}
			}
		}
		
		// Verify server to client data
		if (clientHelper->ReceiveBuffers.Num() == 50)
		{
			for (int i = 0; i < 50; ++i)
			{
				TArray<uint8>& receivebuf = clientHelper->ReceiveBuffers[i];
				TestTrue("Client received packet should not be empty", receivebuf.Num() > 0);
				if (receivebuf.Num() > 0)
				{
					TestEqual("Client received data should match", receivebuf[0], static_cast<uint8>(i + 100));
				}
			}
		}
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		ObjectDelivererClient->Close();
		ObjectDelivererServer->Close();
		
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsLargeDataTransferTest,
								"ObjectDeliverer.ProtocolTcpIpTls.LargeDataTransferTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for large encrypted data transmission over TLS
 * This test sends larger data packets to verify TLS handles fragmentation and reassembly correctly
 */
bool FProtocolTcpIpTlsLargeDataTransferTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);
	
	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server with data receiving capability
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ObjectDelivererServer->ReceiveData.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnReceive);
	
	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));
	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Setup client
	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	
	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait for TLS handshake and connection to establish
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	// Send larger encrypted data packets (1KB each)
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ObjectDelivererClient]()
	{
		for (int i = 0; i < 10; ++i)
		{
			TArray<uint8> sendbuffer;
			sendbuffer.SetNum(1024);
			for (int j = 0; j < 1024; ++j)
			{
				sendbuffer[j] = (i + j) % 256;
			}
			ObjectDelivererClient->Send(sendbuffer);
		}
		return true;
	}));

	// Wait for all large encrypted data to be received
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	// Verify large encrypted data was correctly received
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper]()
	{
		TestEqual("Server should have received 10 large packets", serverHelper->ReceiveBuffers.Num(), 10);
		
		if (serverHelper->ReceiveBuffers.Num() == 10)
		{
			for (int i = 0; i < 10; ++i)
			{
				TArray<uint8>& receivebuf = serverHelper->ReceiveBuffers[i];
				TestEqual("Received packet size should be 1024 bytes", receivebuf.Num(), 1024);
				
				if (receivebuf.Num() == 1024)
				{
					for (int j = 0; j < 1024; ++j)
					{
						TestEqual("Each byte should match", receivebuf[j], static_cast<uint8>((i + j) % 256));
					}
				}
			}
		}
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		ObjectDelivererClient->Close();
		ObjectDelivererServer->Close();
		
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsInvalidCertificateTest,
								"ObjectDeliverer.ProtocolTcpIpTls.InvalidCertificateTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for connection failure with invalid certificate path
 * This test verifies that the server fails to start when given non-existent certificate files
 */
bool FProtocolTcpIpTlsInvalidCertificateTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	// Try to start server with non-existent certificate files
	FString FakeCertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("NonExistent"), TEXT("fake.crt"));
	FString FakeKeyPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("NonExistent"), TEXT("fake.key"));

	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, FakeCertPath, FakeKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait a bit for initialization
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(2.0f));

	// Server should not have any active connections (failed to start)
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper]()
	{
		TestEqual("Server should have no connections with invalid certificate", serverHelper->ConnectedSocket.Num(), 0);
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererServer]()
	{
		ObjectDelivererServer->Close();
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsServerNotRunningTest,
								"ObjectDeliverer.ProtocolTcpIpTls.ServerNotRunningTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for client connection failure when server is not running
 * This test verifies that the client properly handles connection failures
 */
bool FProtocolTcpIpTlsServerNotRunningTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait for connection attempt to fail (increased from 3.0s to 10.0s for Linux compatibility)
	// Linux environments may take longer to detect TLS connection failures
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(10.0f));

	// Verify client is not connected
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ObjectDelivererClient, clientHelper]()
	{
		TestEqual("Client should not be connected", clientHelper->ConnectedSocket.Num(), 0);
		TestFalse("Client manager should not be connected", ObjectDelivererClient->IsConnected());
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient]()
	{
		ObjectDelivererClient->Close();
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsMultiClientTest,
								"ObjectDeliverer.ProtocolTcpIpTls.MultiClientTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for multiple clients connecting to the same TLS server
 * This test verifies that the server can handle multiple simultaneous TLS connections
 */
bool FProtocolTcpIpTlsMultiClientTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);

	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));

	const FString AbsoluteCertDir = FPaths::ConvertRelativePathToFull(CertPath);
	const FString AbsoluteCertPath = FPaths::ConvertRelativePathToFull(ServerCertPath);
	const FString AbsoluteKeyPath = FPaths::ConvertRelativePathToFull(ServerKeyPath);

	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *AbsoluteCertPath);
	}
	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *AbsoluteCertDir);
	}

	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, AbsoluteCertPath, AbsoluteKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Ensure server socket is listening before starting client connections.
	FPlatformProcess::Sleep(GetTlsTestServerStartupDelaySeconds());

	// Create multiple clients
	const int32 NumClients = 5;
	const float ClientStartStaggerSeconds = GetTlsTestClientStartStaggerSeconds();
	TArray<UObjectDelivererManager*> ClientManagers;
	TArray<UObjectDelivererManagerTestHelper*> ClientHelpers;

	for (int32 i = 0; i < NumClients; ++i)
	{
		auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
		auto clientManager = NewTlsTestObject<UObjectDelivererManager>();
		clientManager->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
		clientManager->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

		auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
		tlsClient->WithPeerVerificationDisabled();
		clientManager->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

		ClientManagers.Add(clientManager);
		ClientHelpers.Add(clientHelper);

		if (ClientStartStaggerSeconds > 0.0f)
		{
			FPlatformProcess::Sleep(ClientStartStaggerSeconds);
		}
	}

	// Wait for all clients to connect
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(GetTlsTestMultiClientConnectWaitSeconds()));

	// Verify all clients connected
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, ClientHelpers, NumClients]()
	{
		TestEqual("Server should have all clients connected", serverHelper->ConnectedSocket.Num(), NumClients);

		for (int32 i = 0; i < NumClients; ++i)
		{
			TestEqual(FString::Printf(TEXT("Client %d should be connected"), i), ClientHelpers[i]->ConnectedSocket.Num(), 1);
		}
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManagers, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		for (auto* ClientManager : ClientManagers)
		{
			ClientManager->Close();
		}
		ObjectDelivererServer->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsClientDisconnectionTest,
								"ObjectDeliverer.ProtocolTcpIpTls.ClientDisconnectionTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for client-initiated disconnection
 * This test verifies that disconnection events are properly triggered when client disconnects
 */
bool FProtocolTcpIpTlsClientDisconnectionTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);

	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));

	const FString AbsoluteCertDir = FPaths::ConvertRelativePathToFull(CertPath);
	const FString AbsoluteCertPath = FPaths::ConvertRelativePathToFull(ServerCertPath);
	const FString AbsoluteKeyPath = FPaths::ConvertRelativePathToFull(ServerKeyPath);

	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *AbsoluteCertPath);
	}
	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *AbsoluteCertDir);
	}

	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, AbsoluteCertPath, AbsoluteKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Ensure server socket is listening before starting client connection.
	FPlatformProcess::Sleep(GetTlsTestServerStartupDelaySeconds());

	// Setup client
	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait for connection
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	// Verify connection established
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, clientHelper]()
	{
		TestEqual("Server should have one connected client", serverHelper->ConnectedSocket.Num(), 1);
		TestEqual("Client should be connected", clientHelper->ConnectedSocket.Num(), 1);
		return true;
	}));

	// Disconnect client
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient]()
	{
		ObjectDelivererClient->Close();
		return true;
	}));

	// Wait for disconnection
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(3.0f));

	// Verify disconnection
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, ObjectDelivererServer, ObjectDelivererClient]()
	{
		TestEqual("Server should receive disconnect callback", serverHelper->DisconnectedSocket.Num(), 1);
		TestEqual("Server should have no active connections after disconnect", ObjectDelivererServer->IsConnected(), false);
		TestEqual("Client should be disconnected", ObjectDelivererClient->IsConnected(), false);
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		ObjectDelivererServer->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsEmptyDataTest,
								"ObjectDeliverer.ProtocolTcpIpTls.EmptyDataTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for handling empty data packets over TLS
 * This test verifies that empty data is handled correctly without causing errors
 */
bool FProtocolTcpIpTlsEmptyDataTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);

	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ObjectDelivererServer->ReceiveData.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));

	const FString AbsoluteCertDir = FPaths::ConvertRelativePathToFull(CertPath);
	const FString AbsoluteCertPath = FPaths::ConvertRelativePathToFull(ServerCertPath);
	const FString AbsoluteKeyPath = FPaths::ConvertRelativePathToFull(ServerKeyPath);

	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *AbsoluteCertPath);
	}
	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *AbsoluteCertDir);
	}

	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, AbsoluteCertPath, AbsoluteKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Ensure server socket is listening before starting client connection.
	FPlatformProcess::Sleep(GetTlsTestServerStartupDelaySeconds());

	// Setup client
	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait until both sides are currently connected before sending.
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, clientHelper, ObjectDelivererServer, ObjectDelivererClient, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (ObjectDelivererServer->IsConnected() && ObjectDelivererClient->IsConnected())
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 20.0)
		{
			TestTrue("Server should be connected before sending", ObjectDelivererServer->IsConnected());
			TestTrue("Client should be connected before sending", ObjectDelivererClient->IsConnected());
			TestTrue("Server should report at least one connect callback before sending", serverHelper->ConnectedSocket.Num() > 0);
			TestTrue("Client should report at least one connect callback before sending", clientHelper->ConnectedSocket.Num() > 0);
			return true;
		}

		return false;
	}));

	// Send empty data
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ObjectDelivererClient]()
	{
		TestTrue("Client should remain connected right before sending empty data", ObjectDelivererClient->IsConnected());
		TArray<uint8> EmptyData;
		ObjectDelivererClient->Send(EmptyData);
		return true;
	}));

	// Wait to ensure no errors occur
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(2.0f));

	// Verify connection still active (no crash)
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ObjectDelivererServer, ObjectDelivererClient]()
	{
		TestTrue("Server should still be connected after empty data", ObjectDelivererServer->IsConnected());
		TestTrue("Client should still be connected after empty data", ObjectDelivererClient->IsConnected());
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		ObjectDelivererClient->Close();
		ObjectDelivererServer->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsVeryLargeDataTest,
								"ObjectDeliverer.ProtocolTcpIpTls.VeryLargeDataTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for very large data transmission over TLS
 * This test sends a large payload (10MB) to verify TLS can handle large data transfers
 */
bool FProtocolTcpIpTlsVeryLargeDataTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();
	const int32 ExpectedLargeDataSize = 10 * 1024 * 1024;

	// Generate self-signed certificate for server
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);

	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ObjectDelivererServer->ReceiveData.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));

	const FString AbsoluteCertDir = FPaths::ConvertRelativePathToFull(CertPath);
	const FString AbsoluteCertPath = FPaths::ConvertRelativePathToFull(ServerCertPath);
	const FString AbsoluteKeyPath = FPaths::ConvertRelativePathToFull(ServerKeyPath);

	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *AbsoluteCertPath);
	}
	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *AbsoluteCertDir);
	}

	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, AbsoluteCertPath, AbsoluteKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Setup client
	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait until both sides report a connection to reduce flakiness on slower runners.
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, clientHelper, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (serverHelper->ConnectedSocket.Num() > 0 && clientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual("Server should have one connected client before large data send", serverHelper->ConnectedSocket.Num(), 1);
			TestEqual("Client should be connected before large data send", clientHelper->ConnectedSocket.Num(), 1);
			return true;
		}

		return false;
	}));

	// Send very large data (10MB)
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient, ExpectedLargeDataSize]()
	{
		TArray<uint8> LargeData;
		LargeData.SetNum(ExpectedLargeDataSize);

		// Fill with pattern for verification
		for (int32 i = 0; i < ExpectedLargeDataSize; ++i)
		{
			LargeData[i] = i % 256;
		}

		ObjectDelivererClient->Send(LargeData);
		return true;
	}));

	// Wait until all bytes are received (or timeout).
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([serverHelper, ExpectedLargeDataSize, StartTime = FPlatformTime::Seconds()]() mutable
	{
		int32 TotalBytes = 0;
		for (const auto& Buffer : serverHelper->ReceiveBuffers)
		{
			TotalBytes += Buffer.Num();
		}

		if (TotalBytes >= ExpectedLargeDataSize)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 45.0)
		{
			return true;
		}

		return false;
	}));

	// Verify large data was received
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, ExpectedLargeDataSize]()
	{
		TestTrue("Server should have received data", serverHelper->ReceiveBuffers.Num() > 0);

		if (serverHelper->ReceiveBuffers.Num() > 0)
		{
			int32 TotalBytes = 0;
			for (const auto& Buffer : serverHelper->ReceiveBuffers)
			{
				TotalBytes += Buffer.Num();
			}
			TestEqual("Total received bytes should be 10MB", TotalBytes, ExpectedLargeDataSize);
		}
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		ObjectDelivererClient->Close();
		ObjectDelivererServer->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsHighFrequencyDataTest,
								"ObjectDeliverer.ProtocolTcpIpTls.HighFrequencyDataTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for high-frequency data transmission over TLS
 * This test sends many small packets rapidly to verify TLS can handle high throughput
 */
bool FProtocolTcpIpTlsHighFrequencyDataTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	auto server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);

	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ObjectDelivererServer->ReceiveData.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));

	const FString AbsoluteCertDir = FPaths::ConvertRelativePathToFull(CertPath);
	const FString AbsoluteCertPath = FPaths::ConvertRelativePathToFull(ServerCertPath);
	const FString AbsoluteKeyPath = FPaths::ConvertRelativePathToFull(ServerKeyPath);

	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *AbsoluteCertPath);
	}
	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *AbsoluteCertDir);
	}

	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, AbsoluteCertPath, AbsoluteKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Setup client
	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait until both sides report a connection to reduce flakiness on slower runners.
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, clientHelper, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (serverHelper->ConnectedSocket.Num() > 0 && clientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual("Server should have one connected client before high-frequency send", serverHelper->ConnectedSocket.Num(), 1);
			TestEqual("Client should be connected before high-frequency send", clientHelper->ConnectedSocket.Num(), 1);
			return true;
		}

		return false;
	}));

	// Send high-frequency data (1000 small packets rapidly)
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ObjectDelivererClient]()
	{
		if (!ObjectDelivererClient->IsConnected())
		{
			AddError(TEXT("Client should be connected before high-frequency send"));
			return true;
		}

		for (int32 i = 0; i < 1000; ++i)
		{
			TArray<uint8> SmallData = { static_cast<uint8>(i % 256) };
			ObjectDelivererClient->Send(SmallData);
		}
		return true;
	}));

	// Wait for all high-frequency data to be received (or timeout).
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([serverHelper, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (serverHelper->ReceiveBuffers.Num() >= 1000)
		{
			return true;
		}

		return (FPlatformTime::Seconds() - StartTime) >= 30.0;
	}));

	// Verify all high-frequency data was received
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper]()
	{
		TestEqual("Server should have received 1000 packets", serverHelper->ReceiveBuffers.Num(), 1000);

		if (serverHelper->ReceiveBuffers.Num() == 1000)
		{
				for (int32 i = 0; i < 1000; ++i)
				{
					TArray<uint8>& Buffer = serverHelper->ReceiveBuffers[i];
					TestTrue("High-frequency packet should not be empty", Buffer.Num() > 0);
					if (Buffer.Num() > 0)
					{
						TestEqual("High-frequency data should match", Buffer[0], static_cast<uint8>(i % 256));
					}
				}
		}
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		ObjectDelivererClient->Close();
		ObjectDelivererServer->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsProtocolVersionCompatibilityTest,
								"ObjectDeliverer.ProtocolTcpIpTls.ProtocolVersionCompatibilityTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for TLS minimum protocol version compatibility
 * This test verifies connections with different minimum TLS protocol versions
 */
bool FProtocolTcpIpTlsProtocolVersionCompatibilityTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	auto server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);

	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server with TLS 1.2
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));

	const FString AbsoluteCertDir = FPaths::ConvertRelativePathToFull(CertPath);
	const FString AbsoluteCertPath = FPaths::ConvertRelativePathToFull(ServerCertPath);
	const FString AbsoluteKeyPath = FPaths::ConvertRelativePathToFull(ServerKeyPath);

	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *AbsoluteCertPath);
	}
	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *AbsoluteCertDir);
	}

	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, AbsoluteCertPath, AbsoluteKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Small delay to ensure server is listening before client connects
	FPlatformProcess::Sleep(0.1f);

	// Setup client with TLS 1.2
	auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererClient = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererClient->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererClient->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
	tlsClient->WithPeerVerificationDisabled();
	ObjectDelivererClient->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Wait for connection
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	// Verify connection established with TLS 1.2
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, clientHelper]()
	{
		TestEqual("Server should have connected client with TLS 1.2", serverHelper->ConnectedSocket.Num(), 1);
		TestEqual("Client should be connected with TLS 1.2", clientHelper->ConnectedSocket.Num(), 1);
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ObjectDelivererClient, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		ObjectDelivererClient->Close();
		ObjectDelivererServer->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsConcurrentMultiClientDataTest,
								"ObjectDeliverer.ProtocolTcpIpTls.ConcurrentMultiClientDataTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

/**
 * Test for concurrent data transmission from multiple clients
 * This test verifies that the server can handle simultaneous data from multiple clients
 */
bool FProtocolTcpIpTlsConcurrentMultiClientDataTest::RunTest(const FString& Parameters)
{
	int32 port = GetAvailableTlsPort();

	// Generate self-signed certificate for server
	auto server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	FString CertPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates"));
	IFileManager::Get().MakeDirectory(*CertPath, true);

	bool CertGenerated = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Certificate generation should succeed", CertGenerated);

	// Setup server
	auto serverHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ObjectDelivererServer = NewTlsTestObject<UObjectDelivererManager>();
	ObjectDelivererServer->Connected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ObjectDelivererServer->Disconnected.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ObjectDelivererServer->ReceiveData.AddDynamic(serverHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	FString ServerCertPath = FPaths::Combine(CertPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(CertPath, TEXT("server.key"));

	const FString AbsoluteCertDir = FPaths::ConvertRelativePathToFull(CertPath);
	const FString AbsoluteCertPath = FPaths::ConvertRelativePathToFull(ServerCertPath);
	const FString AbsoluteKeyPath = FPaths::ConvertRelativePathToFull(ServerKeyPath);

	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *AbsoluteCertPath);
	}
	if (GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR")).IsEmpty())
	{
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *AbsoluteCertDir);
	}

	ObjectDelivererServer->Start(
		UProtocolFactory::CreateProtocolTcpIpServerTls(port, AbsoluteCertPath, AbsoluteKeyPath, EObjectDelivererTlsProtocol::TLSv1_2),
		UPacketRuleFactory::CreatePacketRuleSizeBody());

	// Small delay to ensure server is listening before clients connect
	FPlatformProcess::Sleep(GetTlsTestServerStartupDelaySeconds());

	// Create multiple clients
	const int32 NumClients = 3;
	const float ClientStartStaggerSeconds = GetTlsTestClientStartStaggerSeconds();
	TArray<UObjectDelivererManager*> ClientManagers;
	TArray<UObjectDelivererManagerTestHelper*> ClientHelpers;

	for (int32 i = 0; i < NumClients; ++i)
	{
		auto clientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
		auto clientManager = NewTlsTestObject<UObjectDelivererManager>();
		clientManager->Connected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
		clientManager->Disconnected.AddDynamic(clientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

		auto tlsClient = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), port, true, false, EObjectDelivererTlsProtocol::TLSv1_2);
		tlsClient->WithPeerVerificationDisabled();
		clientManager->Start(tlsClient, UPacketRuleFactory::CreatePacketRuleSizeBody());

		ClientManagers.Add(clientManager);
		ClientHelpers.Add(clientHelper);

		if (ClientStartStaggerSeconds > 0.0f)
		{
			FPlatformProcess::Sleep(ClientStartStaggerSeconds);
		}
	}

	// Wait for all clients to connect
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(GetTlsTestMultiClientConnectWaitSeconds()));

	// Send data from all clients concurrently
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManagers]()
	{
		for (int32 i = 0; i < ClientManagers.Num(); ++i)
		{
			for (int32 j = 0; j < 50; ++j)
			{
				uint8 data = (i * 50 + j) % 256;
				TArray<uint8> sendbuffer = { data };
				ClientManagers[i]->Send(sendbuffer);
			}
		}
		return true;
	}));

	// Wait for all data to be received
	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(15.0f));

	// Verify all data received
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, serverHelper, NumClients]()
	{
		int32 ExpectedPackets = NumClients * 50;
		TestEqual("Server should have received all packets", serverHelper->ReceiveBuffers.Num(), ExpectedPackets);
		return true;
	}));

	// Cleanup
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManagers, ObjectDelivererServer, ServerCertPath, ServerKeyPath]()
	{
		for (auto* ClientManager : ClientManagers)
		{
			ClientManager->Close();
		}
		ObjectDelivererServer->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_COMPLEX_AUTOMATION_TEST(FProtocolTcpIpTlsSelfSignedPinningRequiredTest,
								"ObjectDeliverer.ProtocolTcpIpTls.SelfSignedPinningRequiredTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

void FProtocolTcpIpTlsSelfSignedPinningRequiredTest::GetTests(TArray<FString>& OutBeautifiedNames, TArray<FString>& OutTestCommands) const
{
	OutBeautifiedNames.Add(TEXT("Self-signed certificate without pinning should be rejected"));
	OutTestCommands.Add(TEXT(""));
}

bool FProtocolTcpIpTlsSelfSignedPinningRequiredTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_SelfSignedPinning"));

	IFileManager::Get().MakeDirectory(*OutputPath, true);

	bool Success = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(OutputPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Self-signed certificate generation should succeed", Success);

	FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	const FString PrevCertFile = GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"));
	const FString PrevCertDir = GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"));

	// Create server with self-signed certificate
	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);

	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());

	// Small delay to ensure server is listening before client connects
	FPlatformProcess::Sleep(0.1f);

	// UProtocolTcpIpServerTls::InitializeTls may set SSL_CERT_FILE/SSL_CERT_DIR for process-global convenience.
	// Restore original values so this test is about the client policy, not about trusting the server cert via env vars.
	SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *PrevCertFile);
	SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *PrevCertDir);

	// Create client allowing self-signed but WITHOUT pinning (should be rejected).
	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithAllowSelfSignedCertificates(true);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	UPacketRuleNodivision* PacketRule = NewTlsTestObject<UPacketRuleNodivision>();

	ClientManager->Start(Client, PacketRule);

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ClientHelper]()
	{
		TestEqual("Client should not have connected", ClientHelper->ConnectedSocket.Num(), 0);
		TestFalse("Client should not be connected", ClientManager->IsConnected());

		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([Server, Client, ServerManager, ClientManager, ServerCertPath, ServerKeyPath, PrevCertFile, PrevCertDir]()
	{
		ServerManager->Close();
		ClientManager->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);

		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *PrevCertFile);
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *PrevCertDir);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsSelfSignedPinningRequiredEvenWhenTrustedViaEnvTest,
								"ObjectDeliverer.ProtocolTcpIpTls.SelfSignedPinningRequiredEvenWhenTrustedViaEnvTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsSelfSignedPinningRequiredEvenWhenTrustedViaEnvTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_SelfSignedPinningTrustedViaEnv"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	bool Success = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(OutputPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Self-signed certificate generation should succeed", Success);

	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	const FString PrevCertFile = GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"));
	const FString PrevCertDir = GetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"));

	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);

	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());
	FPlatformProcess::Sleep(0.1f);

	// Keep SSL_CERT_FILE/SSL_CERT_DIR as set by server to ensure trusted-via-env path is covered.
	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithAllowSelfSignedCertificates(true);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ClientManager->Start(Client, NewTlsTestObject<UPacketRuleNodivision>());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ClientHelper]()
	{
		TestEqual("Client should not have connected", ClientHelper->ConnectedSocket.Num(), 0);
		TestFalse("Client should not be connected", ClientManager->IsConnected());
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCertPath, ServerKeyPath, PrevCertFile, PrevCertDir]()
	{
		ServerManager->Close();
		ClientManager->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);

		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_FILE"), *PrevCertFile);
		SetTlsTestEnvironmentVariable(TEXT("SSL_CERT_DIR"), *PrevCertDir);
		return true;
	}));

	return true;
}

IMPLEMENT_COMPLEX_AUTOMATION_TEST(FProtocolTcpIpTlsPinningSuccessTest,
								"ObjectDeliverer.ProtocolTcpIpTls.PinningSuccessTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

void FProtocolTcpIpTlsPinningSuccessTest::GetTests(TArray<FString>& OutBeautifiedNames, TArray<FString>& OutTestCommands) const
{
	OutBeautifiedNames.Add(TEXT("Self-signed certificate with pinning should succeed"));
	OutTestCommands.Add(TEXT(""));
}

bool FProtocolTcpIpTlsPinningSuccessTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_PinningSuccess"));

	IFileManager::Get().MakeDirectory(*OutputPath, true);

	bool Success = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(OutputPath, TEXT("server"), TEXT("server"), 365);
	TestTrue("Self-signed certificate generation should succeed", Success);

	FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	// Extract public key hash for pinning
	FString PublicKeyHash;
	Success = UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(ServerCertPath, PublicKeyHash);
	TestTrue("Public key hash extraction should succeed", Success);

	OD_LOG(Log, TEXT("Extracted public key hash for pinning: %s"), *PublicKeyHash);

	// Create server with self-signed certificate
	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);

	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());

	// Small delay to ensure server is listening before client connects
	FPlatformProcess::Sleep(0.1f);

	// Create client WITH pinning (should succeed)
	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithAllowSelfSignedCertificates(true);
	Client->WithPinnedPublicKey(PublicKeyHash);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	UPacketRuleSizeBody* PacketRule = UPacketRuleFactory::CreatePacketRuleSizeBody();

	ClientManager->Start(Client, PacketRule);

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ServerManager]()
	{
		// Client should successfully connect with pinning
		TestTrue("Client should be connected", ClientManager->IsConnected());
		TestTrue("Server should be listening", ServerManager->IsConnected());

		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([Server, Client, ServerManager, ClientManager, ServerCertPath, ServerKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsPinningMismatchTest,
								"ObjectDeliverer.ProtocolTcpIpTls.PinningMismatchTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsPinningMismatchTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();

	// Create two different self-signed certificates:
	// - Server uses Certificate A
	// - Client pins public key hash from Certificate B (should fail)
	const FString CertDirA = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_PinningMismatch_A"));
	const FString CertDirB = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_PinningMismatch_B"));
	IFileManager::Get().MakeDirectory(*CertDirA, true);
	IFileManager::Get().MakeDirectory(*CertDirB, true);

	TestTrue("Self-signed certificate A generation should succeed",
		UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertDirA, TEXT("serverA"), TEXT("serverA"), 365));
	TestTrue("Self-signed certificate B generation should succeed",
		UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(CertDirB, TEXT("serverB"), TEXT("serverB"), 365));

	const FString ServerCertPath = FPaths::Combine(CertDirA, TEXT("serverA.crt"));
	const FString ServerKeyPath = FPaths::Combine(CertDirA, TEXT("serverA.key"));
	const FString WrongCertPath = FPaths::Combine(CertDirB, TEXT("serverB.crt"));
	const FString WrongKeyPath = FPaths::Combine(CertDirB, TEXT("serverB.key"));

	FString WrongPublicKeyHash;
	TestTrue("Public key hash extraction for certificate B should succeed",
		UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(WrongCertPath, WrongPublicKeyHash));

	// Start server with certificate A
	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());

	// Small delay to ensure server is listening before client connects
	FPlatformProcess::Sleep(0.1f);

	// Start client verifying + allowing self-signed, but pinning wrong key (certificate B)
	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithAllowSelfSignedCertificates(true);
	Client->WithPinnedPublicKey(WrongPublicKeyHash);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ClientManager->Start(Client, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ClientHelper]()
	{
		TestEqual("Client should not have connected", ClientHelper->ConnectedSocket.Num(), 0);
		TestFalse("Client should not be connected", ClientManager->IsConnected());
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCertPath, ServerKeyPath, WrongCertPath, WrongKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		IFileManager::Get().Delete(*WrongCertPath, true, true);
		IFileManager::Get().Delete(*WrongKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsPinningSuccessCallOrderTest,
								"ObjectDeliverer.ProtocolTcpIpTls.PinningSuccessCallOrderTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsPinningSuccessCallOrderTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_PinningSuccessCallOrder"));

	IFileManager::Get().MakeDirectory(*OutputPath, true);

	TestTrue("Self-signed certificate generation should succeed",
		UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(OutputPath, TEXT("server"), TEXT("server"), 365));

	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	FString PublicKeyHash;
	TestTrue("Public key hash extraction should succeed",
		UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(ServerCertPath, PublicKeyHash));

	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());

	FPlatformProcess::Sleep(0.1f);

	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithAllowSelfSignedCertificates(true);
	Client->WithCertificateVerification();
	Client->WithPinnedPublicKey(PublicKeyHash);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Start(Client, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ServerManager]()
	{
		TestTrue("Client should be connected regardless of call order", ClientManager->IsConnected());
		TestTrue("Server should be listening", ServerManager->IsConnected());
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCertPath, ServerKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsIdentityDnsMatchTest,
								"ObjectDeliverer.ProtocolTcpIpTls.IdentityDnsMatchTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsIdentityDnsMatchTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_IdentityDnsMatch"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("localhost"));

	TestTrue("Self-signed certificate generation should succeed",
		UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(
			OutputPath, TEXT("server"), TEXT("server"), 365, TEXT("US"), TEXT("ObjectDeliverer"), TEXT("localhost"), SubjectAltDnsNames));

	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));
	FString PublicKeyHash;
	TestTrue("Public key hash extraction should succeed",
		UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(ServerCertPath, PublicKeyHash));

	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());
	FPlatformProcess::Sleep(0.1f);

	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithAllowSelfSignedCertificates(true);
	Client->WithPinnedPublicKey(PublicKeyHash);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Start(Client, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager]()
	{
		TestTrue("Client should be connected with matching DNS identity", ClientManager->IsConnected());
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCertPath, ServerKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsIdentityDnsMismatchTest,
								"ObjectDeliverer.ProtocolTcpIpTls.IdentityDnsMismatchTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsIdentityDnsMismatchTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_IdentityDnsMismatch"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("example.com"));

	TestTrue("Self-signed certificate generation should succeed",
		UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(
			OutputPath, TEXT("server"), TEXT("server"), 365, TEXT("US"), TEXT("ObjectDeliverer"), TEXT("example.com"), SubjectAltDnsNames));

	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));
	FString PublicKeyHash;
	TestTrue("Public key hash extraction should succeed",
		UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(ServerCertPath, PublicKeyHash));

	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());
	FPlatformProcess::Sleep(0.1f);

	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithAllowSelfSignedCertificates(true);
	Client->WithPinnedPublicKey(PublicKeyHash);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Start(Client, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ClientHelper]()
	{
		TestFalse("Client should not connect with mismatched DNS identity", ClientManager->IsConnected());
		TestEqual("Client should not report connected sockets", ClientHelper->ConnectedSocket.Num(), 0);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCertPath, ServerKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsIdentityIpMatchTest,
								"ObjectDeliverer.ProtocolTcpIpTls.IdentityIpMatchTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsIdentityIpMatchTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_IdentityIpMatch"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	TArray<FString> SubjectAltIpAddresses;
	SubjectAltIpAddresses.Add(TEXT("127.0.0.1"));

	TestTrue("Self-signed certificate generation should succeed",
		UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(
			OutputPath, TEXT("server"), TEXT("server"), 365, TEXT("US"), TEXT("ObjectDeliverer"), TEXT("localhost"), TArray<FString>(), SubjectAltIpAddresses));

	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));
	FString PublicKeyHash;
	TestTrue("Public key hash extraction should succeed",
		UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(ServerCertPath, PublicKeyHash));

	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());
	FPlatformProcess::Sleep(0.1f);

	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("127.0.0.1"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithAllowSelfSignedCertificates(true);
	Client->WithPinnedPublicKey(PublicKeyHash);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Start(Client, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager]()
	{
		TestTrue("Client should connect with matching IP SAN", ClientManager->IsConnected());
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCertPath, ServerKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsIdentityIpMismatchTest,
								"ObjectDeliverer.ProtocolTcpIpTls.IdentityIpMismatchTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsIdentityIpMismatchTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_IdentityIpMismatch"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	TArray<FString> SubjectAltIpAddresses;
	SubjectAltIpAddresses.Add(TEXT("127.0.0.1"));

	TestTrue("Self-signed certificate generation should succeed",
		UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(
			OutputPath, TEXT("server"), TEXT("server"), 365, TEXT("US"), TEXT("ObjectDeliverer"), TEXT("localhost"), TArray<FString>(), SubjectAltIpAddresses));

	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));
	FString PublicKeyHash;
	TestTrue("Public key hash extraction should succeed",
		UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(ServerCertPath, PublicKeyHash));

	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());
	FPlatformProcess::Sleep(0.1f);

	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("127.0.0.2"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithAllowSelfSignedCertificates(true);
	Client->WithPinnedPublicKey(PublicKeyHash);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Start(Client, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));
	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ClientHelper]()
	{
		TestFalse("Client should not connect with mismatched IP identity", ClientManager->IsConnected());
		TestEqual("Client should not report connected sockets", ClientHelper->ConnectedSocket.Num(), 0);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCertPath, ServerKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsPinnedPublicKeyFromFileTest,
								"ObjectDeliverer.ProtocolTcpIpTls.PinnedPublicKeyFromFileTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsPinnedPublicKeyFromFileTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();

	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_PinningFromFile"));
	
	// Clean up any existing files from previous test runs to avoid stale data
	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));
	const FString HashFilePath = FPaths::Combine(OutputPath, TEXT("server_public_key_hash.txt"));
	const FString PubKeyFilePath = FPaths::Combine(OutputPath, TEXT("server.pubkey.txt"));
	
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);
	IFileManager::Get().Delete(*HashFilePath, true, true);
	IFileManager::Get().Delete(*PubKeyFilePath, true, true);
	
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	TestTrue("Self-signed certificate generation should succeed",
		UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(OutputPath, TEXT("server"), TEXT("server"), 365));

	TestTrue("Public key hash file generation should succeed",
		UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(ServerCertPath, HashFilePath));
	TestTrue("Public key hash file should exist", FPaths::FileExists(HashFilePath));

	// Small delay to ensure file system has fully written the files (helps on Mac/Windows)
	FPlatformProcess::Sleep(0.1f);

	// Start server
	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());

	// Small delay to ensure server is listening before client connects
	FPlatformProcess::Sleep(0.1f);

	// Start client using pin loaded from file.
	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithAllowSelfSignedCertificates(true);
	Client->WithPinnedPublicKeyFromFile(HashFilePath);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Start(Client, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ServerManager]()
	{
		TestTrue("Client should be connected", ClientManager->IsConnected());
		TestTrue("Server should be listening", ServerManager->IsConnected());
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCertPath, ServerKeyPath, HashFilePath, PubKeyFilePath]()
	{
		ServerManager->Close();
		ClientManager->Close();

		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		IFileManager::Get().Delete(*HashFilePath, true, true);
		IFileManager::Get().Delete(*PubKeyFilePath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsPinnedPublicKeyFromEmptyFilePathWithPeerVerificationDisabledTest,
								"ObjectDeliverer.ProtocolTcpIpTls.PinnedPublicKeyFromEmptyFilePathWithPeerVerificationDisabledTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsPinnedPublicKeyFromEmptyFilePathWithPeerVerificationDisabledTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_PinningEmptyPathPeerVerificationDisabled"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);

	TestTrue("Self-signed certificate generation should succeed",
		UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(OutputPath, TEXT("server"), TEXT("server"), 365));

	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());
	FPlatformProcess::Sleep(0.1f);

	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("127.0.0.1"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);

	Client->WithPinnedPublicKeyFromFile(TEXT(""));
	Client->WithPeerVerificationDisabled();

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Start(Client, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ClientHelper]()
	{
		TestFalse("Client should not connect when pinned key was requested but file path is empty", ClientManager->IsConnected());
		TestEqual("Client should not report connected sockets", ClientHelper->ConnectedSocket.Num(), 0);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCertPath, ServerKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}


IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsCustomCaTrustValidationTest,
								"ObjectDeliverer.ProtocolTcpIpTls.CustomCaTrustValidationTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsCustomCaTrustValidationTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_CustomCa"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	const FString CaCertPath = FPaths::Combine(OutputPath, TEXT("custom_ca.crt"));
	const FString CaKeyPath = FPaths::Combine(OutputPath, TEXT("custom_ca.key"));
	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	IFileManager::Get().Delete(*CaCertPath, true, true);
	IFileManager::Get().Delete(*CaKeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);

	TestTrue(TEXT("Custom CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath));

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("localhost"));
	TestTrue(TEXT("Server certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("server"),
			TEXT("server"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("localhost"),
			SubjectAltDnsNames,
			TArray<FString>()));

	UProtocolTcpIpServerTls* Server = NewTlsTestObject<UProtocolTcpIpServerTls>();
	Server->InitializeTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	UObjectDelivererManager* ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Start(Server, NewTlsTestObject<UPacketRuleNodivision>());
	FPlatformProcess::Sleep(0.1f);

	UProtocolTcpIpClientTls* Client = NewTlsTestObject<UProtocolTcpIpClientTls>();
	Client->InitializeTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	Client->WithCertificateVerification();
	Client->WithTrustedCaCertificate(CaCertPath);

	UObjectDelivererManager* ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Start(Client, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager]()
	{
		TestTrue(TEXT("Client should connect when custom CA certificate is configured"), ClientManager->IsConnected());
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, CaCertPath, CaKeyPath, ServerCertPath, ServerKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*CaCertPath, true, true);
		IFileManager::Get().Delete(*CaKeyPath, true, true);
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsCustomCaRejectMismatchedKeyTest,
								"ObjectDeliverer.ProtocolTcpIpTls.CustomCaRejectMismatchedKeyTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsCustomCaRejectMismatchedKeyTest::RunTest(const FString& Parameters)
{
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_CustomCaMismatch"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	const FString Ca1CertPath = FPaths::Combine(OutputPath, TEXT("custom_ca_1.crt"));
	const FString Ca1KeyPath = FPaths::Combine(OutputPath, TEXT("custom_ca_1.key"));
	const FString Ca2CertPath = FPaths::Combine(OutputPath, TEXT("custom_ca_2.crt"));
	const FString Ca2KeyPath = FPaths::Combine(OutputPath, TEXT("custom_ca_2.key"));
	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	IFileManager::Get().Delete(*Ca1CertPath, true, true);
	IFileManager::Get().Delete(*Ca1KeyPath, true, true);
	IFileManager::Get().Delete(*Ca2CertPath, true, true);
	IFileManager::Get().Delete(*Ca2KeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);

	TestTrue(TEXT("First custom CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath, TEXT("custom_ca_1"), TEXT("custom_ca_1")));
	TestTrue(TEXT("Second custom CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath, TEXT("custom_ca_2"), TEXT("custom_ca_2")));

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("localhost"));

	const bool bGeneratedWithMismatchedCaPair = UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
		OutputPath,
		TEXT("server"),
		TEXT("server"),
		Ca1CertPath,
		Ca2KeyPath,
		365,
		TEXT("US"),
		TEXT("ObjectDeliverer"),
		TEXT("localhost"),
		SubjectAltDnsNames,
		TArray<FString>());

	TestFalse(TEXT("Server certificate generation should fail when CA certificate and key do not match"), bGeneratedWithMismatchedCaPair);
	TestFalse(TEXT("Server certificate should not be generated with mismatched CA certificate/key"), FPaths::FileExists(ServerCertPath));
	TestFalse(TEXT("Server key should not be generated with mismatched CA certificate/key"), FPaths::FileExists(ServerKeyPath));

	IFileManager::Get().Delete(*Ca1CertPath, true, true);
	IFileManager::Get().Delete(*Ca1KeyPath, true, true);
	IFileManager::Get().Delete(*Ca2CertPath, true, true);
	IFileManager::Get().Delete(*Ca2KeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsMutualAuthRequiredSuccessTest,
								"ObjectDeliverer.ProtocolTcpIpTls.MutualAuthRequiredSuccessTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsMutualAuthRequiredSuccessTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_MutualAuthRequiredSuccess"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	const FString CaCertPath = FPaths::Combine(OutputPath, TEXT("custom_ca.crt"));
	const FString CaKeyPath = FPaths::Combine(OutputPath, TEXT("custom_ca.key"));
	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));
	const FString ClientCertPath = FPaths::Combine(OutputPath, TEXT("client.crt"));
	const FString ClientKeyPath = FPaths::Combine(OutputPath, TEXT("client.key"));

	IFileManager::Get().Delete(*CaCertPath, true, true);
	IFileManager::Get().Delete(*CaKeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);
	IFileManager::Get().Delete(*ClientCertPath, true, true);
	IFileManager::Get().Delete(*ClientKeyPath, true, true);

	TestTrue(TEXT("Custom CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath));

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("localhost"));

	TestTrue(TEXT("Server certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("server"),
			TEXT("server"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("localhost"),
			SubjectAltDnsNames,
			TArray<FString>()));

	TestTrue(TEXT("Client certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("client"),
			TEXT("client"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("client"),
			TArray<FString>(),
			TArray<FString>(),
			TEXT("clientAuth")));

	auto ServerHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Connected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ServerManager->Disconnected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto ServerProtocol = UProtocolFactory::CreateProtocolTcpIpServerTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	ServerProtocol->WithClientAuthMode(EObjectDelivererClientAuthMode::Required);
	ServerProtocol->WithClientCaBundle(CaCertPath);
	ServerManager->Start(ServerProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	FPlatformProcess::Sleep(0.1f);

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ClientProtocol->WithCertificateVerification();
	ClientProtocol->WithTrustedCaCertificate(CaCertPath);
	ClientProtocol->WithClientCertificate(ClientCertPath, ClientKeyPath);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ServerHelper, ClientHelper]()
	{
		TestEqual(TEXT("Server should have one connected client in mTLS required mode"), ServerHelper->ConnectedSocket.Num(), 1);
		TestEqual(TEXT("Client should be connected in mTLS required mode"), ClientHelper->ConnectedSocket.Num(), 1);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, CaCertPath, CaKeyPath, ServerCertPath, ServerKeyPath, ClientCertPath, ClientKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*CaCertPath, true, true);
		IFileManager::Get().Delete(*CaKeyPath, true, true);
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		IFileManager::Get().Delete(*ClientCertPath, true, true);
		IFileManager::Get().Delete(*ClientKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsMutualAuthRequiredWithoutClientCertificateTest,
								"ObjectDeliverer.ProtocolTcpIpTls.MutualAuthRequiredWithoutClientCertificateTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsMutualAuthOptionalWithClientCertificateSuccessTest,
								"ObjectDeliverer.ProtocolTcpIpTls.MutualAuthOptionalWithClientCertificateSuccessTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsMutualAuthOptionalWithClientCertificateSuccessTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_MutualAuthOptionalWithClientCert"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	const FString CaCertPath = FPaths::Combine(OutputPath, TEXT("custom_ca.crt"));
	const FString CaKeyPath = FPaths::Combine(OutputPath, TEXT("custom_ca.key"));
	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));
	const FString ClientCertPath = FPaths::Combine(OutputPath, TEXT("client.crt"));
	const FString ClientKeyPath = FPaths::Combine(OutputPath, TEXT("client.key"));

	IFileManager::Get().Delete(*CaCertPath, true, true);
	IFileManager::Get().Delete(*CaKeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);
	IFileManager::Get().Delete(*ClientCertPath, true, true);
	IFileManager::Get().Delete(*ClientKeyPath, true, true);

	TestTrue(TEXT("Custom CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath));

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("localhost"));

	TestTrue(TEXT("Server certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("server"),
			TEXT("server"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("localhost"),
			SubjectAltDnsNames,
			TArray<FString>()));

	TestTrue(TEXT("Client certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("client"),
			TEXT("client"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("client"),
			TArray<FString>(),
			TArray<FString>(),
			TEXT("clientAuth")));

	auto ServerHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Connected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ServerManager->Disconnected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto ServerProtocol = UProtocolFactory::CreateProtocolTcpIpServerTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	ServerProtocol->WithClientAuthMode(EObjectDelivererClientAuthMode::Optional);
	ServerProtocol->WithClientCaBundle(CaCertPath);
	ServerManager->Start(ServerProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	FPlatformProcess::Sleep(0.1f);

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ClientProtocol->WithCertificateVerification();
	ClientProtocol->WithTrustedCaCertificate(CaCertPath);
	ClientProtocol->WithClientCertificate(ClientCertPath, ClientKeyPath);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ServerHelper, ClientHelper]()
	{
		TestEqual(TEXT("Server should have one connected client in mTLS optional mode"), ServerHelper->ConnectedSocket.Num(), 1);
		TestEqual(TEXT("Client should be connected in mTLS optional mode"), ClientHelper->ConnectedSocket.Num(), 1);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, CaCertPath, CaKeyPath, ServerCertPath, ServerKeyPath, ClientCertPath, ClientKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*CaCertPath, true, true);
		IFileManager::Get().Delete(*CaKeyPath, true, true);
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		IFileManager::Get().Delete(*ClientCertPath, true, true);
		IFileManager::Get().Delete(*ClientKeyPath, true, true);
		return true;
	}));

	return true;
}

bool FProtocolTcpIpTlsMutualAuthRequiredWithoutClientCertificateTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_MutualAuthRequiredNoClientCert"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	const FString CaCertPath = FPaths::Combine(OutputPath, TEXT("custom_ca.crt"));
	const FString CaKeyPath = FPaths::Combine(OutputPath, TEXT("custom_ca.key"));
	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	IFileManager::Get().Delete(*CaCertPath, true, true);
	IFileManager::Get().Delete(*CaKeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);

	TestTrue(TEXT("Custom CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath));

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("localhost"));

	TestTrue(TEXT("Server certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("server"),
			TEXT("server"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("localhost"),
			SubjectAltDnsNames,
			TArray<FString>()));

	auto ServerHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Connected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ServerManager->Disconnected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto ServerProtocol = UProtocolFactory::CreateProtocolTcpIpServerTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	ServerProtocol->WithClientAuthMode(EObjectDelivererClientAuthMode::Required);
	ServerProtocol->WithClientCaBundle(CaCertPath);
	ServerManager->Start(ServerProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	FPlatformProcess::Sleep(0.1f);

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ClientProtocol->WithCertificateVerification();
	ClientProtocol->WithTrustedCaCertificate(CaCertPath);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientHelper, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (ClientHelper->DisconnectedSocket.Num() > 0)
		{
			return true;
		}

		return (FPlatformTime::Seconds() - StartTime) >= 8.0;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ClientHelper, ServerHelper]()
	{
		TestFalse(TEXT("Client should not connect without client certificate when mTLS required"), ClientManager->IsConnected());
		TestEqual(TEXT("Server should not accept client without certificate when mTLS required"), ServerHelper->ConnectedSocket.Num(), 0);
		TestTrue(TEXT("Client connected callback, if emitted, must be followed by disconnected callback when mTLS required and no client certificate"),
			ClientHelper->ConnectedSocket.Num() == 0 || ClientHelper->DisconnectedSocket.Num() > 0);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, CaCertPath, CaKeyPath, ServerCertPath, ServerKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*CaCertPath, true, true);
		IFileManager::Get().Delete(*CaKeyPath, true, true);
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsMutualAuthRejectUnknownClientCaTest,
								"ObjectDeliverer.ProtocolTcpIpTls.MutualAuthRejectUnknownClientCaTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsMutualAuthRejectUnknownClientCaTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_MutualAuthRejectUnknownClientCa"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	const FString ServerCaCertPath = FPaths::Combine(OutputPath, TEXT("server_ca.crt"));
	const FString ServerCaKeyPath = FPaths::Combine(OutputPath, TEXT("server_ca.key"));
	const FString ClientCaCertPath = FPaths::Combine(OutputPath, TEXT("client_ca.crt"));
	const FString ClientCaKeyPath = FPaths::Combine(OutputPath, TEXT("client_ca.key"));
	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));
	const FString ClientCertPath = FPaths::Combine(OutputPath, TEXT("client.crt"));
	const FString ClientKeyPath = FPaths::Combine(OutputPath, TEXT("client.key"));

	IFileManager::Get().Delete(*ServerCaCertPath, true, true);
	IFileManager::Get().Delete(*ServerCaKeyPath, true, true);
	IFileManager::Get().Delete(*ClientCaCertPath, true, true);
	IFileManager::Get().Delete(*ClientCaKeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);
	IFileManager::Get().Delete(*ClientCertPath, true, true);
	IFileManager::Get().Delete(*ClientKeyPath, true, true);

	TestTrue(TEXT("Server CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath, TEXT("server_ca"), TEXT("server_ca")));
	TestTrue(TEXT("Client CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath, TEXT("client_ca"), TEXT("client_ca")));

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("localhost"));

	TestTrue(TEXT("Server certificate signed by server CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("server"),
			TEXT("server"),
			ServerCaCertPath,
			ServerCaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("localhost"),
			SubjectAltDnsNames,
			TArray<FString>()));

	TestTrue(TEXT("Client certificate signed by client CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("client"),
			TEXT("client"),
			ClientCaCertPath,
			ClientCaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("client"),
			TArray<FString>(),
			TArray<FString>(),
			TEXT("clientAuth")));

	auto ServerHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Connected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ServerManager->Disconnected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto ServerProtocol = UProtocolFactory::CreateProtocolTcpIpServerTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	ServerProtocol->WithClientAuthMode(EObjectDelivererClientAuthMode::Required);
	ServerProtocol->WithClientCaBundle(ServerCaCertPath);
	ServerManager->Start(ServerProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	FPlatformProcess::Sleep(0.1f);

	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ClientProtocol->WithCertificateVerification();
	ClientProtocol->WithTrustedCaCertificate(ServerCaCertPath);
	ClientProtocol->WithClientCertificate(ClientCertPath, ClientKeyPath);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ServerHelper]()
	{
		TestFalse(TEXT("Client should not connect with unknown client CA in mTLS required mode"), ClientManager->IsConnected());
		TestEqual(TEXT("Server should reject client certificate signed by unknown CA"), ServerHelper->ConnectedSocket.Num(), 0);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, ServerCaCertPath, ServerCaKeyPath, ClientCaCertPath, ClientCaKeyPath, ServerCertPath, ServerKeyPath, ClientCertPath, ClientKeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*ServerCaCertPath, true, true);
		IFileManager::Get().Delete(*ServerCaKeyPath, true, true);
		IFileManager::Get().Delete(*ClientCaCertPath, true, true);
		IFileManager::Get().Delete(*ClientCaKeyPath, true, true);
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		IFileManager::Get().Delete(*ClientCertPath, true, true);
		IFileManager::Get().Delete(*ClientKeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsMutualAuthClientCertificateKeyMismatchTest,
								"ObjectDeliverer.ProtocolTcpIpTls.MutualAuthClientCertificateKeyMismatchTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsMutualAuthClientCertificateKeyMismatchTest::RunTest(const FString& Parameters)
{
	const int32 Port = GetAvailableTlsPort();
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_MutualAuthClientKeyMismatch"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	const FString CaCertPath = FPaths::Combine(OutputPath, TEXT("custom_ca.crt"));
	const FString CaKeyPath = FPaths::Combine(OutputPath, TEXT("custom_ca.key"));
	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));
	const FString Client1CertPath = FPaths::Combine(OutputPath, TEXT("client_1.crt"));
	const FString Client1KeyPath = FPaths::Combine(OutputPath, TEXT("client_1.key"));
	const FString Client2CertPath = FPaths::Combine(OutputPath, TEXT("client_2.crt"));
	const FString Client2KeyPath = FPaths::Combine(OutputPath, TEXT("client_2.key"));

	IFileManager::Get().Delete(*CaCertPath, true, true);
	IFileManager::Get().Delete(*CaKeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);
	IFileManager::Get().Delete(*Client1CertPath, true, true);
	IFileManager::Get().Delete(*Client1KeyPath, true, true);
	IFileManager::Get().Delete(*Client2CertPath, true, true);
	IFileManager::Get().Delete(*Client2KeyPath, true, true);

	TestTrue(TEXT("Custom CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath));

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("localhost"));

	TestTrue(TEXT("Server certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("server"),
			TEXT("server"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("localhost"),
			SubjectAltDnsNames,
			TArray<FString>()));

	TestTrue(TEXT("First client certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("client_1"),
			TEXT("client_1"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("client-1"),
			TArray<FString>(),
			TArray<FString>(),
			TEXT("clientAuth")));

	TestTrue(TEXT("Second client certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("client_2"),
			TEXT("client_2"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("client-2"),
			TArray<FString>(),
			TArray<FString>(),
			TEXT("clientAuth")));

	auto ServerHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ServerManager = NewTlsTestObject<UObjectDelivererManager>();
	ServerManager->Connected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ServerManager->Disconnected.AddDynamic(ServerHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto ServerProtocol = UProtocolFactory::CreateProtocolTcpIpServerTls(Port, ServerCertPath, ServerKeyPath, EObjectDelivererTlsProtocol::TLSv1_2);
	ServerProtocol->WithClientAuthMode(EObjectDelivererClientAuthMode::Required);
	ServerProtocol->WithClientCaBundle(CaCertPath);
	ServerManager->Start(ServerProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	FPlatformProcess::Sleep(0.1f);

	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(TEXT("localhost"), Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ClientProtocol->WithCertificateVerification();
	ClientProtocol->WithTrustedCaCertificate(CaCertPath);
	ClientProtocol->WithClientCertificate(Client1CertPath, Client2KeyPath);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(5.0f));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientManager, ServerHelper]()
	{
		TestFalse(TEXT("Client should not connect when certificate and key do not match"), ClientManager->IsConnected());
		TestEqual(TEXT("Server should reject mismatched client certificate/key"), ServerHelper->ConnectedSocket.Num(), 0);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ServerManager, ClientManager, CaCertPath, CaKeyPath, ServerCertPath, ServerKeyPath, Client1CertPath, Client1KeyPath, Client2CertPath, Client2KeyPath]()
	{
		ServerManager->Close();
		ClientManager->Close();
		IFileManager::Get().Delete(*CaCertPath, true, true);
		IFileManager::Get().Delete(*CaKeyPath, true, true);
		IFileManager::Get().Delete(*ServerCertPath, true, true);
		IFileManager::Get().Delete(*ServerKeyPath, true, true);
		IFileManager::Get().Delete(*Client1CertPath, true, true);
		IFileManager::Get().Delete(*Client1KeyPath, true, true);
		IFileManager::Get().Delete(*Client2CertPath, true, true);
		IFileManager::Get().Delete(*Client2KeyPath, true, true);
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsExternalFixedLengthEchoTest,
								"ObjectDeliverer.ProtocolTcpIpTlsExternal.FixedLengthEchoTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsExternalFixedLengthEchoTest::RunTest(const FString& Parameters)
{
	if (!IsExternalTlsEchoTestEnabled())
	{
		AddWarning(TEXT("Skip external TLS echo test. Set OD_TLS_EXTERNAL_ENABLED=1 to enable."));
		return true;
	}

	const FString Host = GetExternalTlsEchoHost();
	const int32 Port = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_FIXED_PORT"), 9101);
	const int32 FixedLength = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_FIXED_LENGTH"), 32);

	if (FixedLength <= 0)
	{
		AddError(TEXT("OD_TLS_EXTERNAL_FIXED_LENGTH must be greater than 0."));
		return false;
	}

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ClientManager->ReceiveData.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(Host, Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ConfigureExternalTlsClient(ClientProtocol);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleFixedLength(FixedLength));

	TArray<uint8> ExpectedBuffer;
	ExpectedBuffer.SetNum(FixedLength);
	for (int32 i = 0; i < FixedLength; ++i)
	{
		ExpectedBuffer[i] = static_cast<uint8>(i % 251);
	}
	auto bConnectionFailed = MakeShared<bool>(false);

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, Host, Port, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (ClientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			*bConnectionFailed = true;
			AddError(FString::Printf(TEXT("External TLS fixed-length echo test failed: unable to connect to %s:%d within timeout."), *Host, Port));
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		ClientManager->Send(ExpectedBuffer);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		if (ClientHelper->ReceiveBuffers.Num() >= 1)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual(TEXT("Client should receive one echoed packet from fixed-length server"), ClientHelper->ReceiveBuffers.Num(), 1);
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		TestEqual(TEXT("Received packet count"), ClientHelper->ReceiveBuffers.Num(), 1);
		if (ClientHelper->ReceiveBuffers.Num() == 1)
		{
			const TArray<uint8>& Actual = ClientHelper->ReceiveBuffers[0];
			bool bMatch = Actual.Num() == ExpectedBuffer.Num();
			if (bMatch)
			{
				for (int32 i = 0; i < Actual.Num(); ++i)
				{
					if (Actual[i] != ExpectedBuffer[i])
					{
						bMatch = false;
						break;
					}
				}
			}
			TestTrue(TEXT("FixedLength echo should match sent payload"), bMatch);
		}
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager]()
	{
		ClientManager->Close();
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsExternalSizeBodyEchoTest,
								"ObjectDeliverer.ProtocolTcpIpTlsExternal.SizeBodyEchoTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsExternalSizeBodyEchoTest::RunTest(const FString& Parameters)
{
	if (!IsExternalTlsEchoTestEnabled())
	{
		AddWarning(TEXT("Skip external TLS echo test. Set OD_TLS_EXTERNAL_ENABLED=1 to enable."));
		return true;
	}

	const FString Host = GetExternalTlsEchoHost();
	const int32 Port = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_SIZEBODY_PORT"), 9102);

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ClientManager->ReceiveData.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(Host, Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ConfigureExternalTlsClient(ClientProtocol);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody(4, ECNBufferEndian::Big));

	const TArray<uint8> ExpectedBuffer = { 't', 'l', 's', '-', 's', 'i', 'z', 'e', 'b', 'o', 'd', 'y' };
	auto bConnectionFailed = MakeShared<bool>(false);

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, Host, Port, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (ClientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			*bConnectionFailed = true;
			AddError(FString::Printf(TEXT("External TLS size-body echo test failed: unable to connect to %s:%d within timeout."), *Host, Port));
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		ClientManager->Send(ExpectedBuffer);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		if (ClientHelper->ReceiveBuffers.Num() >= 1)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual(TEXT("Client should receive one echoed packet from size-body server"), ClientHelper->ReceiveBuffers.Num(), 1);
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		TestEqual(TEXT("Received packet count"), ClientHelper->ReceiveBuffers.Num(), 1);
		if (ClientHelper->ReceiveBuffers.Num() == 1)
		{
			const TArray<uint8>& Actual = ClientHelper->ReceiveBuffers[0];
			bool bMatch = Actual.Num() == ExpectedBuffer.Num();
			if (bMatch)
			{
				for (int32 i = 0; i < Actual.Num(); ++i)
				{
					if (Actual[i] != ExpectedBuffer[i])
					{
						bMatch = false;
						break;
					}
				}
			}
			TestTrue(TEXT("SizeBody echo should match sent payload"), bMatch);
		}
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager]()
	{
		ClientManager->Close();
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsExternalTerminateEchoTest,
								"ObjectDeliverer.ProtocolTcpIpTlsExternal.TerminateEchoTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsExternalTerminateEchoTest::RunTest(const FString& Parameters)
{
	if (!IsExternalTlsEchoTestEnabled())
	{
		AddWarning(TEXT("Skip external TLS echo test. Set OD_TLS_EXTERNAL_ENABLED=1 to enable."));
		return true;
	}

	const FString Host = GetExternalTlsEchoHost();
	const int32 Port = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_TERMINATE_PORT"), 9103);
	const int32 TerminateByte = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_TERMINATE_BYTE"), 10);

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ClientManager->ReceiveData.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(Host, Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ConfigureExternalTlsClient(ClientProtocol);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleTerminate({ static_cast<uint8>(TerminateByte) }));

	const TArray<uint8> ExpectedBuffer = { 't', 'l', 's', '-', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e' };
	auto bConnectionFailed = MakeShared<bool>(false);

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, Host, Port, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (ClientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			*bConnectionFailed = true;
			AddError(FString::Printf(TEXT("External TLS terminate echo test failed: unable to connect to %s:%d within timeout."), *Host, Port));
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		ClientManager->Send(ExpectedBuffer);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		if (ClientHelper->ReceiveBuffers.Num() >= 1)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual(TEXT("Client should receive one echoed packet from terminate server"), ClientHelper->ReceiveBuffers.Num(), 1);
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		TestEqual(TEXT("Received packet count"), ClientHelper->ReceiveBuffers.Num(), 1);
		if (ClientHelper->ReceiveBuffers.Num() == 1)
		{
			const TArray<uint8>& Actual = ClientHelper->ReceiveBuffers[0];
			bool bMatch = Actual.Num() == ExpectedBuffer.Num();
			if (bMatch)
			{
				for (int32 i = 0; i < Actual.Num(); ++i)
				{
					if (Actual[i] != ExpectedBuffer[i])
					{
						bMatch = false;
						break;
					}
				}
			}
			TestTrue(TEXT("Terminate echo should match sent payload"), bMatch);
		}
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager]()
	{
		ClientManager->Close();
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsExternalTls13FixedLengthEchoTest,
								"ObjectDeliverer.ProtocolTcpIpTlsExternal.Tls13FixedLengthEchoTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsExternalTls13FixedLengthEchoTest::RunTest(const FString& Parameters)
{
	if (!IsExternalTlsEchoTestEnabled())
	{
		AddWarning(TEXT("Skip external TLS 1.3 echo test. Set OD_TLS_EXTERNAL_ENABLED=1 to enable."));
		return true;
	}

	const FString Host = GetExternalTlsEchoHost();
	const int32 Port = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_TLS13_FIXED_PORT"), 9104);
	const int32 FixedLength = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_TLS13_FIXED_LENGTH"), 32);

	if (FixedLength <= 0)
	{
		AddError(TEXT("OD_TLS_EXTERNAL_TLS13_FIXED_LENGTH must be greater than 0."));
		return false;
	}

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ClientManager->ReceiveData.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(Host, Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ConfigureExternalTlsClient(ClientProtocol);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleFixedLength(FixedLength));

	TArray<uint8> ExpectedBuffer;
	ExpectedBuffer.SetNum(FixedLength);
	for (int32 i = 0; i < FixedLength; ++i)
	{
		ExpectedBuffer[i] = static_cast<uint8>(i % 251);
	}
	auto bConnectionFailed = MakeShared<bool>(false);

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, Host, Port, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (ClientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			*bConnectionFailed = true;
			AddError(FString::Printf(TEXT("External TLS 1.3 fixed-length echo test failed: unable to connect to %s:%d within timeout."), *Host, Port));
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		ClientManager->Send(ExpectedBuffer);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		if (ClientHelper->ReceiveBuffers.Num() >= 1)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual(TEXT("Client should receive one echoed packet from TLS 1.3 fixed-length server"), ClientHelper->ReceiveBuffers.Num(), 1);
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		TestEqual(TEXT("Received packet count"), ClientHelper->ReceiveBuffers.Num(), 1);
		if (ClientHelper->ReceiveBuffers.Num() == 1)
		{
			const TArray<uint8>& Actual = ClientHelper->ReceiveBuffers[0];
			bool bMatch = Actual.Num() == ExpectedBuffer.Num();
			if (bMatch)
			{
				for (int32 i = 0; i < Actual.Num(); ++i)
				{
					if (Actual[i] != ExpectedBuffer[i])
					{
						bMatch = false;
						break;
					}
				}
			}
			TestTrue(TEXT("TLS 1.3 FixedLength echo should match sent payload"), bMatch);
		}
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager]()
	{
		ClientManager->Close();
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsExternalTls13SizeBodyEchoTest,
								"ObjectDeliverer.ProtocolTcpIpTlsExternal.Tls13SizeBodyEchoTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsExternalTls13SizeBodyEchoTest::RunTest(const FString& Parameters)
{
	if (!IsExternalTlsEchoTestEnabled())
	{
		AddWarning(TEXT("Skip external TLS 1.3 echo test. Set OD_TLS_EXTERNAL_ENABLED=1 to enable."));
		return true;
	}

	const FString Host = GetExternalTlsEchoHost();
	const int32 Port = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_TLS13_SIZEBODY_PORT"), 9105);

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ClientManager->ReceiveData.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(Host, Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ConfigureExternalTlsClient(ClientProtocol);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody(4, ECNBufferEndian::Big));

	const TArray<uint8> ExpectedBuffer = { 't', 'l', 's', '1', '-', 's', 'i', 'z', 'e', 'b', 'o', 'd', 'y' };
	auto bConnectionFailed = MakeShared<bool>(false);

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, Host, Port, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (ClientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			*bConnectionFailed = true;
			AddError(FString::Printf(TEXT("External TLS 1.3 size-body echo test failed: unable to connect to %s:%d within timeout."), *Host, Port));
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		ClientManager->Send(ExpectedBuffer);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		if (ClientHelper->ReceiveBuffers.Num() >= 1)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual(TEXT("Client should receive one echoed packet from TLS 1.3 size-body server"), ClientHelper->ReceiveBuffers.Num(), 1);
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		TestEqual(TEXT("Received packet count"), ClientHelper->ReceiveBuffers.Num(), 1);
		if (ClientHelper->ReceiveBuffers.Num() == 1)
		{
			const TArray<uint8>& Actual = ClientHelper->ReceiveBuffers[0];
			bool bMatch = Actual.Num() == ExpectedBuffer.Num();
			if (bMatch)
			{
				for (int32 i = 0; i < Actual.Num(); ++i)
				{
					if (Actual[i] != ExpectedBuffer[i])
					{
						bMatch = false;
						break;
					}
				}
			}
			TestTrue(TEXT("TLS 1.3 SizeBody echo should match sent payload"), bMatch);
		}
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager]()
	{
		ClientManager->Close();
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsExternalTls13TerminateEchoTest,
								"ObjectDeliverer.ProtocolTcpIpTlsExternal.Tls13TerminateEchoTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsExternalTls13TerminateEchoTest::RunTest(const FString& Parameters)
{
	if (!IsExternalTlsEchoTestEnabled())
	{
		AddWarning(TEXT("Skip external TLS 1.3 echo test. Set OD_TLS_EXTERNAL_ENABLED=1 to enable."));
		return true;
	}

	const FString Host = GetExternalTlsEchoHost();
	const int32 Port = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_TLS13_TERMINATE_PORT"), 9106);
	const int32 TerminateByte = GetTlsTestEnvironmentInt(TEXT("OD_TLS_EXTERNAL_TLS13_TERMINATE_BYTE"), 10);

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);
	ClientManager->ReceiveData.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnReceive);

	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(Host, Port, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ConfigureExternalTlsClient(ClientProtocol);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleTerminate({ static_cast<uint8>(TerminateByte) }));

	const TArray<uint8> ExpectedBuffer = { 't', 'l', 's', '1', '-', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e' };
	auto bConnectionFailed = MakeShared<bool>(false);

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, Host, Port, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (ClientHelper->ConnectedSocket.Num() > 0)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			*bConnectionFailed = true;
			AddError(FString::Printf(TEXT("External TLS 1.3 terminate echo test failed: unable to connect to %s:%d within timeout."), *Host, Port));
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		ClientManager->Send(ExpectedBuffer);
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, bConnectionFailed, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		if (ClientHelper->ReceiveBuffers.Num() >= 1)
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= 15.0)
		{
			TestEqual(TEXT("Client should receive one echoed packet from TLS 1.3 terminate server"), ClientHelper->ReceiveBuffers.Num(), 1);
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, ExpectedBuffer, bConnectionFailed]()
	{
		if (*bConnectionFailed)
		{
			return true;
		}
		TestEqual(TEXT("Received packet count"), ClientHelper->ReceiveBuffers.Num(), 1);
		if (ClientHelper->ReceiveBuffers.Num() == 1)
		{
			const TArray<uint8>& Actual = ClientHelper->ReceiveBuffers[0];
			bool bMatch = Actual.Num() == ExpectedBuffer.Num();
			if (bMatch)
			{
				for (int32 i = 0; i < Actual.Num(); ++i)
				{
					if (Actual[i] != ExpectedBuffer[i])
					{
						bMatch = false;
						break;
					}
				}
			}
			TestTrue(TEXT("TLS 1.3 Terminate echo should match sent payload"), bMatch);
		}
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager]()
	{
		ClientManager->Close();
		return true;
	}));

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsExternalCloseWrongPortReturnsPromptlyTest,
								"ObjectDeliverer.ProtocolTcpIpTlsExternal.CloseWrongPortReturnsPromptlyTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsExternalCloseWrongPortReturnsPromptlyTest::RunTest(const FString& Parameters)
{
	if (!IsExternalTlsEchoTestEnabled())
	{
		AddWarning(TEXT("Skip external TLS wrong-port close test. Set OD_TLS_EXTERNAL_ENABLED=1 to enable."));
		return true;
	}

	const FString Host = GetExternalTlsEchoHost();
	const int32 WrongPort = GetExternalTlsWrongPort();
	constexpr double CloseTimeoutSeconds = 2.0;
	constexpr double ConnectKickoffDelaySeconds = 0.1;

	auto ClientHelper = NewTlsTestObject<UObjectDelivererManagerTestHelper>();
	auto ClientManager = NewTlsTestObject<UObjectDelivererManager>();
	ClientManager->Connected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnConnect);
	ClientManager->Disconnected.AddDynamic(ClientHelper, &UObjectDelivererManagerTestHelper::OnDisConnect);

	auto ClientProtocol = UProtocolFactory::CreateProtocolTcpIpClientTls(Host, WrongPort, false, false, EObjectDelivererTlsProtocol::TLSv1_2);
	ConfigureExternalTlsClient(ClientProtocol);
	ClientManager->Start(ClientProtocol, UPacketRuleFactory::CreatePacketRuleSizeBody());

	auto bCloseCompleted = MakeShared<TAtomic<bool>>(false);
	auto CloseDurationSeconds = MakeShared<double>(-1.0);

	ADD_LATENT_AUTOMATION_COMMAND(FEngineWaitLatentCommand(ConnectKickoffDelaySeconds));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([ClientManager, bCloseCompleted, CloseDurationSeconds]()
	{
		Async(EAsyncExecution::Thread, [ClientManager, bCloseCompleted, CloseDurationSeconds]()
		{
			const double StartTime = FPlatformTime::Seconds();
			ClientManager->Close();
			*CloseDurationSeconds = FPlatformTime::Seconds() - StartTime;
			bCloseCompleted->Store(true);
		});
		return true;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, bCloseCompleted, Host, WrongPort, CloseTimeoutSeconds, StartTime = FPlatformTime::Seconds()]() mutable
	{
		if (bCloseCompleted->Load())
		{
			return true;
		}

		if ((FPlatformTime::Seconds() - StartTime) >= CloseTimeoutSeconds)
		{
			AddError(FString::Printf(TEXT("Close() did not return within %.2f seconds while canceling TLS connect to %s:%d."), CloseTimeoutSeconds, *Host, WrongPort));
			return true;
		}

		return false;
	}));

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, ClientHelper, CloseDurationSeconds, Host, WrongPort, CloseTimeoutSeconds]()
	{
		TestEqual(TEXT("Wrong-port external TLS connect should not report a successful connection"), ClientHelper->ConnectedSocket.Num(), 0);
		TestTrue(FString::Printf(TEXT("Close() should return within %.2f seconds for %s:%d"), CloseTimeoutSeconds, *Host, WrongPort), *CloseDurationSeconds >= 0.0 && *CloseDurationSeconds < CloseTimeoutSeconds);
		return true;
	}));

	return true;
}

#if PLATFORM_UNIX
IMPLEMENT_SIMPLE_AUTOMATION_TEST(FProtocolTcpIpTlsSignedServerKeyPermissionTest,
								"ObjectDeliverer.ProtocolTcpIpTls.SignedServerKeyPermissionTest",
								EAutomationTestFlags::EditorContext | EAutomationTestFlags::ClientContext | EAutomationTestFlags::EngineFilter)

bool FProtocolTcpIpTlsSignedServerKeyPermissionTest::RunTest(const FString& Parameters)
{
	const FString OutputPath = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("TestCertificates_CustomCaPermissions"));
	IFileManager::Get().MakeDirectory(*OutputPath, true);

	const FString CaCertPath = FPaths::Combine(OutputPath, TEXT("custom_ca.crt"));
	const FString CaKeyPath = FPaths::Combine(OutputPath, TEXT("custom_ca.key"));
	const FString ServerCertPath = FPaths::Combine(OutputPath, TEXT("server.crt"));
	const FString ServerKeyPath = FPaths::Combine(OutputPath, TEXT("server.key"));

	IFileManager::Get().Delete(*CaCertPath, true, true);
	IFileManager::Get().Delete(*CaKeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);

	TestTrue(TEXT("Custom CA generation should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(OutputPath));

	TArray<FString> SubjectAltDnsNames;
	SubjectAltDnsNames.Add(TEXT("localhost"));

	TestTrue(TEXT("Server certificate signed by custom CA should succeed"),
		UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
			OutputPath,
			TEXT("server"),
			TEXT("server"),
			CaCertPath,
			CaKeyPath,
			365,
			TEXT("US"),
			TEXT("ObjectDeliverer"),
			TEXT("localhost"),
			SubjectAltDnsNames,
			TArray<FString>()));

	TestTrue(TEXT("Signed server private key file should exist"), FPaths::FileExists(ServerKeyPath));

	FString AbsoluteServerKeyPath = IFileManager::Get().ConvertToAbsolutePathForExternalAppForRead(*ServerKeyPath);
	struct stat ServerKeyStat;
	if (stat(TCHAR_TO_UTF8(*AbsoluteServerKeyPath), &ServerKeyStat) == 0)
	{
		mode_t ServerKeyPerms = ServerKeyStat.st_mode & 0777;
		TestEqual(TEXT("Signed server private key should have 600 permissions"), ServerKeyPerms, static_cast<mode_t>(0600));
	}
	else
	{
		AddWarning(FString::Printf(TEXT("Could not stat signed server private key file: %s"), *ServerKeyPath));
	}

	IFileManager::Get().Delete(*CaCertPath, true, true);
	IFileManager::Get().Delete(*CaKeyPath, true, true);
	IFileManager::Get().Delete(*ServerCertPath, true, true);
	IFileManager::Get().Delete(*ServerKeyPath, true, true);

	return true;
}
#endif


#endif
