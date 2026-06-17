// Copyright 2019 ayumax. All Rights Reserved.
#include "Utils/ObjectDelivererCertificateGenerator.h"

#include "Misc/Paths.h"
#include "Misc/FileHelper.h"
#include "HAL/PlatformFileManager.h"
#include "HAL/PlatformMisc.h"
#include "Utils/ODLog.h"

#ifdef UI
	#pragma push_macro("UI")
	#undef UI
	#define OBJECTDELIVERER_RESTORE_UI 1
#endif

#define UI UE_OPENSSL_UI
#define OBJECTDELIVERER_UNDEF_OPENSSL_UI 1

#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509v3.h"

#ifdef OBJECTDELIVERER_UNDEF_OPENSSL_UI
	#undef UI
	#undef OBJECTDELIVERER_UNDEF_OPENSSL_UI
#endif

#ifdef OBJECTDELIVERER_RESTORE_UI
	#pragma pop_macro("UI")
	#undef OBJECTDELIVERER_RESTORE_UI
#endif

#include <cstdio>

#if PLATFORM_UNIX
	#include <sys/stat.h>
	#include <cerrno>
#endif

namespace
{
#if PLATFORM_UNIX
	FCriticalSection GCertificateGeneratorUmaskCriticalSection;
#endif

	FString ToExternalAbsolutePath(const FString& InPath)
	{
		if (InPath.IsEmpty())
		{
			return InPath;
		}

		FString OutPath = IFileManager::Get().ConvertToAbsolutePathForExternalAppForRead(*InPath);
		FPaths::NormalizeFilename(OutPath);
		return OutPath;
	}

	bool LoadFileBytesForOpenSslRead(const FString& InPath, TArray<uint8>& OutBytes)
	{
		const FString NormalizedPath = ToExternalAbsolutePath(InPath);
		if (!FFileHelper::LoadFileToArray(OutBytes, *NormalizedPath))
		{
			return false;
		}
		return true;
	}

}


bool UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(
	const FString& OutputDirectory,
	const FString& CertificateFilename,
	const FString& KeyFilename,
	int32 Days,
	const FString& Country,
	const FString& Organization,
	const FString& CommonName,
	const TArray<FString>& SubjectAltDnsNames,
	const TArray<FString>& SubjectAltIpAddresses)
{
	// WARNING: This function generates and stores sensitive cryptographic material to disk.
	// Security considerations:
	// - The private key will be written to disk unencrypted
	// - File permissions will be set to restrict access (Unix systems only)
	// - Ensure OutputDirectory is on a secure filesystem with appropriate access controls
	// - This is intended for development/testing purposes only
	// - For production, use proper certificate management
	OD_LOG(Warning, TEXT("GenerateSelfSignedCertificate: Writing sensitive cryptographic material to %s. Ensure this directory has appropriate security controls."), *OutputDirectory);

	// Normalize and create output directory
	FString NormalizedOutputDir = ToExternalAbsolutePath(OutputDirectory);
	FPaths::NormalizeFilename(NormalizedOutputDir);
	
	if (!FPaths::DirectoryExists(NormalizedOutputDir))
	{
		if (!IFileManager::Get().MakeDirectory(*NormalizedOutputDir, true))
		{
			OD_LOG(Error, TEXT("Failed to create output directory: %s"), *NormalizedOutputDir);
			return false;
		}
	}

	FString CertPath = ToExternalAbsolutePath(FPaths::Combine(NormalizedOutputDir, CertificateFilename + TEXT(".crt")));
	FString PrivateKeyPath = ToExternalAbsolutePath(FPaths::Combine(NormalizedOutputDir, KeyFilename + TEXT(".key")));

	FCertificateInfo CertInfo;
	CertInfo.Country = Country;
	CertInfo.Organization = Organization;
	CertInfo.CommonName = CommonName;
	CertInfo.SubjectAltDnsNames = SubjectAltDnsNames;
	CertInfo.SubjectAltIpAddresses = SubjectAltIpAddresses;

	bool bSuccess = GenerateCertificateInternal(CertPath, PrivateKeyPath, Days, CertInfo);

	if (bSuccess)
	{
		// Extract and save public key hash for easy pinning
		const FString PublicKeyHashOutputPath = ToExternalAbsolutePath(FPaths::Combine(NormalizedOutputDir, CertificateFilename + TEXT(".pubkey.txt")));
		if (ExtractPublicKeyHash(CertPath, PublicKeyHashOutputPath))
		{
			OD_LOG(Log, TEXT("Public key hash saved to %s"), *PublicKeyHashOutputPath);
		}
	}

	return bSuccess;
}

bool UObjectDelivererCertificateGenerator::GenerateCertificateAuthority(
	const FString& OutputDirectory,
	const FString& CertificateFilename,
	const FString& KeyFilename,
	int32 Days,
	const FString& Country,
	const FString& Organization,
	const FString& CommonName)
{
	const FString NormalizedOutputDir = ToExternalAbsolutePath(OutputDirectory);

	if (!FPaths::DirectoryExists(NormalizedOutputDir))
	{
		if (!IFileManager::Get().MakeDirectory(*NormalizedOutputDir, true))
		{
			OD_LOG(Error, TEXT("Failed to create output directory: %s"), *NormalizedOutputDir);
			return false;
		}
	}

	return GenerateSelfSignedCertificate(
		NormalizedOutputDir,
		CertificateFilename,
		KeyFilename,
		Days,
		Country,
		Organization,
		CommonName);
}

bool UObjectDelivererCertificateGenerator::GenerateCertificateSignedByAuthority(
	const FString& OutputDirectory,
	const FString& CertificateFilename,
	const FString& KeyFilename,
	const FString& CaCertificatePath,
	const FString& CaPrivateKeyPath,
	int32 Days,
	const FString& Country,
	const FString& Organization,
	const FString& CommonName,
	const TArray<FString>& SubjectAltDnsNames,
	const TArray<FString>& SubjectAltIpAddresses,
	const FString& ExtendedKeyUsage)
{
	const FString NormalizedOutputDir = ToExternalAbsolutePath(OutputDirectory);
	const FString NormalizedCaCertificatePath = ToExternalAbsolutePath(CaCertificatePath);
	const FString NormalizedCaPrivateKeyPath = ToExternalAbsolutePath(CaPrivateKeyPath);

	if (!FPaths::FileExists(NormalizedCaCertificatePath) || !FPaths::FileExists(NormalizedCaPrivateKeyPath))
	{
		OD_LOG(Error, TEXT("CA certificate or private key does not exist"));
		return false;
	}

	if (!FPaths::DirectoryExists(NormalizedOutputDir))
	{
		if (!IFileManager::Get().MakeDirectory(*NormalizedOutputDir, true))
		{
			OD_LOG(Error, TEXT("Failed to create output directory: %s"), *NormalizedOutputDir);
			return false;
		}
	}

	const FString CertPath = ToExternalAbsolutePath(FPaths::Combine(NormalizedOutputDir, CertificateFilename + TEXT(".crt")));
	const FString PrivateKeyPath = ToExternalAbsolutePath(FPaths::Combine(NormalizedOutputDir, KeyFilename + TEXT(".key")));

	TArray<uint8> CaCertBytes;
	if (!LoadFileBytesForOpenSslRead(NormalizedCaCertificatePath, CaCertBytes) || CaCertBytes.Num() == 0)
	{
		OD_LOG(Error, TEXT("Failed to open CA certificate: %s"), *NormalizedCaCertificatePath);
		return false;
	}

	BIO* CaCertBio = BIO_new_mem_buf(CaCertBytes.GetData(), CaCertBytes.Num());
	if (!CaCertBio)
	{
		OD_LOG(Error, TEXT("Failed to open CA certificate: %s"), *NormalizedCaCertificatePath);
		return false;
	}
	X509* CaCert = PEM_read_bio_X509(CaCertBio, nullptr, nullptr, nullptr);
	BIO_free(CaCertBio);
	if (!CaCert)
	{
		OD_LOG(Error, TEXT("Failed to read CA certificate: %s"), *NormalizedCaCertificatePath);
		return false;
	}

	TArray<uint8> CaKeyBytes;
	if (!LoadFileBytesForOpenSslRead(NormalizedCaPrivateKeyPath, CaKeyBytes) || CaKeyBytes.Num() == 0)
	{
		X509_free(CaCert);
		OD_LOG(Error, TEXT("Failed to open CA private key: %s"), *NormalizedCaPrivateKeyPath);
		return false;
	}

	BIO* CaKeyBio = BIO_new_mem_buf(CaKeyBytes.GetData(), CaKeyBytes.Num());
	if (!CaKeyBio)
	{
		X509_free(CaCert);
		OD_LOG(Error, TEXT("Failed to open CA private key: %s"), *NormalizedCaPrivateKeyPath);
		return false;
	}
	EVP_PKEY* CaKey = PEM_read_bio_PrivateKey(CaKeyBio, nullptr, nullptr, nullptr);
	BIO_free(CaKeyBio);
	if (!CaKey)
	{
		X509_free(CaCert);
		OD_LOG(Error, TEXT("Failed to read CA private key: %s"), *NormalizedCaPrivateKeyPath);
		return false;
	}

	if (X509_check_private_key(CaCert, CaKey) != 1)
	{
		EVP_PKEY_free(CaKey);
		X509_free(CaCert);
		OD_LOG(Warning, TEXT("CA certificate and private key do not match"));
		return false;
	}

	EVP_PKEY* ServerKey = EVP_PKEY_new();
	EVP_PKEY_CTX* KeyGenCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if (!KeyGenCtx || EVP_PKEY_keygen_init(KeyGenCtx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_keygen_bits(KeyGenCtx, 2048) <= 0 ||
		EVP_PKEY_keygen(KeyGenCtx, &ServerKey) <= 0)
	{
		if (KeyGenCtx) EVP_PKEY_CTX_free(KeyGenCtx);
		if (ServerKey) EVP_PKEY_free(ServerKey);
		EVP_PKEY_free(CaKey);
		X509_free(CaCert);
		OD_LOG(Error, TEXT("Failed to generate server key pair"));
		return false;
	}
	EVP_PKEY_CTX_free(KeyGenCtx);

	X509* ServerCert = X509_new();
	if (!ServerCert)
	{
		EVP_PKEY_free(ServerKey);
		EVP_PKEY_free(CaKey);
		X509_free(CaCert);
		OD_LOG(Error, TEXT("Failed to create server certificate"));
		return false;
	}

	if (X509_set_version(ServerCert, 2) != 1 ||
		ASN1_INTEGER_set(X509_get_serialNumber(ServerCert), FDateTime::UtcNow().ToUnixTimestamp()) != 1 ||
		X509_gmtime_adj(X509_get_notBefore(ServerCert), 0) == nullptr ||
		X509_gmtime_adj(X509_get_notAfter(ServerCert), 60 * 60 * 24 * Days) == nullptr)
	{
		X509_free(ServerCert);
		EVP_PKEY_free(ServerKey);
		EVP_PKEY_free(CaKey);
		X509_free(CaCert);
		OD_LOG(Error, TEXT("Failed to configure server certificate validity"));
		return false;
	}

	X509_NAME* SubjectName = X509_get_subject_name(ServerCert);
	const FTCHARToUTF8 CountryUtf8(*Country);
	const FTCHARToUTF8 OrganizationUtf8(*Organization);
	const FTCHARToUTF8 CommonNameUtf8(*CommonName);
	X509_NAME_add_entry_by_txt(SubjectName, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(CountryUtf8.Get()), -1, -1, 0);
	X509_NAME_add_entry_by_txt(SubjectName, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(OrganizationUtf8.Get()), -1, -1, 0);
	X509_NAME_add_entry_by_txt(SubjectName, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(CommonNameUtf8.Get()), -1, -1, 0);
	X509_set_subject_name(ServerCert, SubjectName);
	X509_set_issuer_name(ServerCert, X509_get_subject_name(CaCert));
	X509_set_pubkey(ServerCert, ServerKey);

	auto AddExtension = [](X509* Cert, int Nid, const char* Value)
	{
		X509_EXTENSION* Ext = X509V3_EXT_conf_nid(nullptr, nullptr, Nid, const_cast<char*>(Value));
		if (!Ext)
		{
			return false;
		}
		X509_add_ext(Cert, Ext, -1);
		X509_EXTENSION_free(Ext);
		return true;
	};

	const FString EffectiveExtendedKeyUsage = ExtendedKeyUsage.IsEmpty() ? TEXT("serverAuth") : ExtendedKeyUsage;
	const FTCHARToUTF8 ExtendedKeyUsageUtf8(*EffectiveExtendedKeyUsage);
	if (!AddExtension(ServerCert, NID_basic_constraints, "critical,CA:FALSE") ||
		!AddExtension(ServerCert, NID_key_usage, "critical,digitalSignature,keyEncipherment") ||
		!AddExtension(ServerCert, NID_ext_key_usage, ExtendedKeyUsageUtf8.Get()))
	{
		X509_free(ServerCert);
		EVP_PKEY_free(ServerKey);
		EVP_PKEY_free(CaKey);
		X509_free(CaCert);
		OD_LOG(Error, TEXT("Failed to add server certificate extensions"));
		return false;
	}

	if (SubjectAltDnsNames.Num() > 0 || SubjectAltIpAddresses.Num() > 0)
	{
		TArray<FString> Entries;
		for (const FString& DnsName : SubjectAltDnsNames)
		{
			Entries.Add(FString::Printf(TEXT("DNS:%s"), *DnsName));
		}
		for (const FString& Ip : SubjectAltIpAddresses)
		{
			Entries.Add(FString::Printf(TEXT("IP:%s"), *Ip));
		}
		const FString SubjectAltNameValue = FString::Join(Entries, TEXT(","));
		const FTCHARToUTF8 SubjectAltNameUtf8(*SubjectAltNameValue);
		if (!AddExtension(ServerCert, NID_subject_alt_name, SubjectAltNameUtf8.Get()))
		{
			X509_free(ServerCert);
			EVP_PKEY_free(ServerKey);
			EVP_PKEY_free(CaKey);
			X509_free(CaCert);
			OD_LOG(Error, TEXT("Failed to add server certificate SAN extension"));
			return false;
		}
	}

	if (X509_sign(ServerCert, CaKey, EVP_sha256()) <= 0)
	{
		X509_free(ServerCert);
		EVP_PKEY_free(ServerKey);
		EVP_PKEY_free(CaKey);
		X509_free(CaCert);
		OD_LOG(Error, TEXT("Failed to sign server certificate with CA key"));
		return false;
	}

	BIO* ServerCertBio = BIO_new(BIO_s_mem());
	BIO* ServerKeyBio = BIO_new(BIO_s_mem());
	if (!ServerCertBio || !ServerKeyBio || PEM_write_bio_X509(ServerCertBio, ServerCert) != 1 ||
		PEM_write_bio_PrivateKey(ServerKeyBio, ServerKey, nullptr, nullptr, 0, nullptr, nullptr) != 1)
	{
		if (ServerCertBio) BIO_free(ServerCertBio);
		if (ServerKeyBio) BIO_free(ServerKeyBio);
		X509_free(ServerCert);
		EVP_PKEY_free(ServerKey);
		EVP_PKEY_free(CaKey);
		X509_free(CaCert);
		OD_LOG(Error, TEXT("Failed to serialize signed certificate or key"));
		return false;
	}

	char* CertData = nullptr;
	long CertLen = BIO_get_mem_data(ServerCertBio, &CertData);
	TArray<uint8> CertBytes;
	CertBytes.SetNumUninitialized(CertLen);
	FMemory::Memcpy(CertBytes.GetData(), CertData, CertLen);
	BIO_free(ServerCertBio);

	char* KeyData = nullptr;
	long KeyLen = BIO_get_mem_data(ServerKeyBio, &KeyData);
	TArray<uint8> KeyBytes;
	KeyBytes.SetNumUninitialized(KeyLen);
	FMemory::Memcpy(KeyBytes.GetData(), KeyData, KeyLen);
	BIO_free(ServerKeyBio);

	const bool bCertSaved = FFileHelper::SaveArrayToFile(CertBytes, *CertPath);

	bool bKeySaved = false;
#if PLATFORM_UNIX
	FScopeLock UmaskLock(&GCertificateGeneratorUmaskCriticalSection);

	mode_t OldUmask = umask(0077);
	bKeySaved = FFileHelper::SaveArrayToFile(KeyBytes, *PrivateKeyPath);
	umask(OldUmask);
#else
	bKeySaved = FFileHelper::SaveArrayToFile(KeyBytes, *PrivateKeyPath);
#endif

	X509_free(ServerCert);
	EVP_PKEY_free(ServerKey);
	EVP_PKEY_free(CaKey);
	X509_free(CaCert);

	if (!bCertSaved || !bKeySaved)
	{
		if (bCertSaved)
		{
			IFileManager::Get().Delete(*CertPath, false, true, true);
		}

		if (bKeySaved)
		{
			IFileManager::Get().Delete(*PrivateKeyPath, false, true, true);
		}

		OD_LOG(Error, TEXT("Failed to save signed server certificate or key"));
		return false;
	}

	return true;
}

bool UObjectDelivererCertificateGenerator::GenerateCertificateInternal(
	const FString& CertPath,
	const FString& PrivateKeyPath,
	int32 Days,
	const FCertificateInfo& CertInfo)
{
	EVP_PKEY* pkey = EVP_PKEY_new();
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || 
		EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
		EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		if (pkey) EVP_PKEY_free(pkey);
		if (ctx) EVP_PKEY_CTX_free(ctx);
		OD_LOG(Error, TEXT("Failed to generate RSA key pair"));
		return false;
	}
	
	EVP_PKEY_CTX_free(ctx);
	
	X509* x509 = X509_new();
	if (!x509)
	{
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to create X509 structure"));
		return false;
	}

	if (X509_set_version(x509, 2) != 1)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to set X509 version"));
		return false;
	}
	
	if (ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) != 1)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to set X509 serial number"));
		return false;
	}
	
	if (X509_gmtime_adj(X509_get_notBefore(x509), 0) == nullptr ||
		X509_gmtime_adj(X509_get_notAfter(x509), 60 * 60 * 24 * Days) == nullptr)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to set X509 validity period"));
		return false;
	}
	
	X509_NAME* name = X509_get_subject_name(x509);
	if (!name)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to get X509 subject name"));
		return false;
	}

	// Convert FString to ANSI for OpenSSL
	const FTCHARToUTF8 CountryUtf8(*CertInfo.Country);
	const FTCHARToUTF8 OrganizationUtf8(*CertInfo.Organization);
	const FTCHARToUTF8 CommonNameUtf8(*CertInfo.CommonName);

	if (X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
		reinterpret_cast<const unsigned char*>(CountryUtf8.Get()), -1, -1, 0) != 1)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to add country (C) to X509 subject name"));
		return false;
	}

	if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
		reinterpret_cast<const unsigned char*>(OrganizationUtf8.Get()), -1, -1, 0) != 1)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to add organization (O) to X509 subject name"));
		return false;
	}

	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		reinterpret_cast<const unsigned char*>(CommonNameUtf8.Get()), -1, -1, 0) != 1)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to add common name (CN) to X509 subject name"));
		return false;
	}
	
	if (X509_set_issuer_name(x509, name) != 1)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to set X509 issuer name"));
		return false;
	}
	
	if (X509_set_pubkey(x509, pkey) != 1)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to set X509 public key"));
		return false;
	}

	// Add CA:TRUE basic constraints and key usage so the generated cert can be used as a trust anchor
	auto AddExtension = [](X509* Cert, int Nid, const char* Value)
	{
		X509_EXTENSION* Ext = X509V3_EXT_conf_nid(nullptr, nullptr, Nid, const_cast<char*>(Value));
		if (!Ext)
		{
			return false;
		}
		X509_add_ext(Cert, Ext, -1);
		X509_EXTENSION_free(Ext);
		return true;
	};

	if (!AddExtension(x509, NID_basic_constraints, "critical,CA:TRUE"))
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to add basic constraints"));
		return false;
	}

	if (!AddExtension(x509, NID_key_usage, "critical,keyCertSign,digitalSignature,keyEncipherment"))
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to add key usage"));
		return false;
	}

	if (CertInfo.SubjectAltDnsNames.Num() > 0 || CertInfo.SubjectAltIpAddresses.Num() > 0)
	{
		TArray<FString> SubjectAltNameEntries;
		for (const FString& DnsName : CertInfo.SubjectAltDnsNames)
		{
			SubjectAltNameEntries.Add(FString::Printf(TEXT("DNS:%s"), *DnsName));
		}
		for (const FString& IpAddress : CertInfo.SubjectAltIpAddresses)
		{
			SubjectAltNameEntries.Add(FString::Printf(TEXT("IP:%s"), *IpAddress));
		}

		const FString SubjectAltNameValue = FString::Join(SubjectAltNameEntries, TEXT(","));
		const FTCHARToUTF8 SubjectAltNameUtf8(*SubjectAltNameValue);
		if (!AddExtension(x509, NID_subject_alt_name, SubjectAltNameUtf8.Get()))
		{
			X509_free(x509);
			EVP_PKEY_free(pkey);
			OD_LOG(Error, TEXT("Failed to add subjectAltName extension"));
			return false;
		}
	}
	
	if (X509_sign(x509, pkey, EVP_sha256()) <= 0)
	{
		X509_free(x509);
		EVP_PKEY_free(pkey);
		OD_LOG(Error, TEXT("Failed to sign X509 certificate"));
		return false;
	}
	
	// Write certificate file
	{
		BIO* CertBio = BIO_new(BIO_s_mem());
		if (!CertBio)
		{
			X509_free(x509);
			EVP_PKEY_free(pkey);
			OD_LOG(Error, TEXT("Failed to create BIO for certificate"));
			return false;
		}

		if (PEM_write_bio_X509(CertBio, x509) != 1)
		{
			BIO_free(CertBio);
			X509_free(x509);
			EVP_PKEY_free(pkey);
			OD_LOG(Error, TEXT("Failed to write certificate to BIO"));
			return false;
		}

		char* CertData = nullptr;
		long CertLen = BIO_get_mem_data(CertBio, &CertData);
		TArray<uint8> CertBytes;
		CertBytes.SetNumUninitialized(CertLen);
		FMemory::Memcpy(CertBytes.GetData(), CertData, CertLen);
		BIO_free(CertBio);

		if (!FFileHelper::SaveArrayToFile(CertBytes, *CertPath))
		{
			X509_free(x509);
			EVP_PKEY_free(pkey);
			OD_LOG(Error, TEXT("Failed to write certificate file"));
			return false;
		}
	}

	// Write private key file
	{
		BIO* KeyBio = BIO_new(BIO_s_mem());
		if (!KeyBio)
		{
			// Clean up certificate file on error
			IFileManager::Get().Delete(*CertPath, false, true, true);
			X509_free(x509);
			EVP_PKEY_free(pkey);
			OD_LOG(Error, TEXT("Failed to create BIO for private key"));
			return false;
		}

		if (PEM_write_bio_PrivateKey(KeyBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1)
		{
			BIO_free(KeyBio);
			// Clean up certificate file on error
			IFileManager::Get().Delete(*CertPath, false, true, true);
			X509_free(x509);
			EVP_PKEY_free(pkey);
			OD_LOG(Error, TEXT("Failed to write private key to BIO"));
			return false;
		}

		char* KeyData = nullptr;
		long KeyLen = BIO_get_mem_data(KeyBio, &KeyData);
		TArray<uint8> KeyBytes;
		KeyBytes.SetNumUninitialized(KeyLen);
		FMemory::Memcpy(KeyBytes.GetData(), KeyData, KeyLen);
		BIO_free(KeyBio);

		// Set restrictive umask before file creation to ensure atomic permission setting (Unix systems only)
		// This prevents the security window between file creation and chmod
		// Note: umask is process-wide, so we use a critical section for thread safety
#if PLATFORM_UNIX
		FScopeLock UmaskLock(&GCertificateGeneratorUmaskCriticalSection);

		mode_t OldUmask = umask(0077); // Set umask to create files with 600 permissions (owner read/write only)

		bool bSaveSuccess = FFileHelper::SaveArrayToFile(KeyBytes, *PrivateKeyPath);

		// Restore umask immediately after file creation
		umask(OldUmask);
#else
		bool bSaveSuccess = FFileHelper::SaveArrayToFile(KeyBytes, *PrivateKeyPath);
#endif

		if (!bSaveSuccess)
		{
			// Clean up certificate file on error
			IFileManager::Get().Delete(*CertPath, false, true, true);
			X509_free(x509);
			EVP_PKEY_free(pkey);
			OD_LOG(Error, TEXT("Failed to write private key file"));
			return false;
		}

		OD_LOG(Log, TEXT("Created private key file with restrictive permissions: %s"), *PrivateKeyPath);
	}

	X509_free(x509);
	EVP_PKEY_free(pkey);

	OD_LOG(Log, TEXT("Generated self-signed certificate at %s and %s"), *CertPath, *PrivateKeyPath);
	OD_LOG(Warning, TEXT("SECURITY: Private key stored unencrypted at %s - protect this file and delete securely when no longer needed"), *PrivateKeyPath);

	return true;
}

bool UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(const FString& CertPath, FString& OutPublicKeyHash)
{
#ifdef UI
	#pragma push_macro("UI")
	#undef UI
	#define OBJECTDELIVERER_RESTORE_UI 1
#endif

#define UI UE_OPENSSL_UI
#define OBJECTDELIVERER_UNDEF_OPENSSL_UI 1

#include "openssl/sha.h"
#include "openssl/pem.h"
#include "openssl/bio.h"

#ifdef OBJECTDELIVERER_UNDEF_OPENSSL_UI
	#undef UI
	#undef OBJECTDELIVERER_UNDEF_OPENSSL_UI
#endif

#ifdef OBJECTDELIVERER_RESTORE_UI
	#pragma pop_macro("UI")
	#undef OBJECTDELIVERER_RESTORE_UI
#endif

	const FString NormalizedCertPath = ToExternalAbsolutePath(CertPath);

	// Read certificate file through UE file I/O. Android OpenSSL file APIs can fail on app-scoped paths.
	TArray<uint8> CertBytes;
	if (!LoadFileBytesForOpenSslRead(NormalizedCertPath, CertBytes) || CertBytes.Num() == 0)
	{
		OD_LOG(Error, TEXT("Failed to open certificate file: %s"), *NormalizedCertPath);
		return false;
	}

	BIO* CertBio = BIO_new_mem_buf(CertBytes.GetData(), CertBytes.Num());
	if (!CertBio)
	{
		OD_LOG(Error, TEXT("Failed to open certificate file: %s"), *NormalizedCertPath);
		return false;
	}

	X509* Cert = PEM_read_bio_X509(CertBio, nullptr, nullptr, nullptr);
	BIO_free(CertBio);

	if (!Cert)
	{
		OD_LOG(Error, TEXT("Failed to read certificate from file: %s"), *NormalizedCertPath);
		return false;
	}

	// Extract public key
	EVP_PKEY* PubKey = X509_get_pubkey(Cert);
	X509_free(Cert);

	if (!PubKey)
	{
		OD_LOG(Error, TEXT("Failed to extract public key from certificate"));
		return false;
	}

	// Serialize public key to DER format
	unsigned char* PubKeyDer = nullptr;
	int PubKeyLen = i2d_PUBKEY(PubKey, &PubKeyDer);
	EVP_PKEY_free(PubKey);

	if (PubKeyLen <= 0)
	{
		OD_LOG(Error, TEXT("Failed to serialize public key"));
		return false;
	}

	// Compute SHA256 hash
	uint8 Hash[SHA256_DIGEST_LENGTH];
	SHA256(PubKeyDer, PubKeyLen, Hash);
	OPENSSL_free(PubKeyDer);

	// Convert to hex string with colons (xx:xx:xx:...)
	OutPublicKeyHash.Empty();
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
	{
		OutPublicKeyHash += FString::Printf(TEXT("%02x"), Hash[i]);
		if (i < SHA256_DIGEST_LENGTH - 1)
		{
			OutPublicKeyHash += TEXT(":");
		}
	}

	OD_LOG(Log, TEXT("Extracted public key hash from certificate: %s"), *OutPublicKeyHash);
	return true;
}

bool UObjectDelivererCertificateGenerator::ExtractPublicKeyHash(const FString& CertPath, const FString& OutputPath)
{
	// First extract the hash to a string
	FString PublicKeyHash;
	if (!ExtractPublicKeyHash(CertPath, PublicKeyHash))
	{
		return false;
	}

	// Create helpful content for the file
	FString FileContent = TEXT("Public Key Hash for TLS Pinning\n");
	FileContent += TEXT("================================\n\n");
	FileContent += TEXT("This file contains the SHA256 hash of the public key from the certificate.\n");
	FileContent += TEXT("Use this hash with ObjectDeliverer's WithPinnedPublicKey() function.\n\n");
	FileContent += TEXT("C++ Usage:\n");
	FileContent += TEXT("  Client->WithPinnedPublicKey(TEXT(\"") + PublicKeyHash + TEXT("\"));\n\n");
	FileContent += TEXT("Blueprint Usage:\n");
	FileContent += TEXT("  Call WithPinnedPublicKey on the TLS client with this string.\n\n");
	FileContent += TEXT("Public Key Hash:\n");
	FileContent += PublicKeyHash + TEXT("\n\n");
	FileContent += TEXT("Generated by ObjectDeliverer Certificate Generator\n");

	const FString NormalizedOutputPath = ToExternalAbsolutePath(OutputPath);

	// Save to file
	if (!FFileHelper::SaveStringToFile(FileContent, *NormalizedOutputPath))
	{
		OD_LOG(Error, TEXT("Failed to save public key hash to file: %s"), *NormalizedOutputPath);
		return false;
	}

	OD_LOG(Log, TEXT("Saved public key hash to %s"), *NormalizedOutputPath);
	return true;
}
