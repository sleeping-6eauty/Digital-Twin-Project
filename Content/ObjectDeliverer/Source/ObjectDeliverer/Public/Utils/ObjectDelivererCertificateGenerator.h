// Copyright 2019 ayumax. All Rights Reserved.
#pragma once

#include "CoreMinimal.h"

#include "ObjectDelivererCertificateGenerator.generated.h"

UCLASS()
class OBJECTDELIVERER_API UObjectDelivererCertificateGenerator : public UObject
{
	GENERATED_BODY()

public:
	/**
	 * Generates a self-signed TLS certificate and private key for development/testing purposes.
	 *
	 * @param OutputDirectory The directory where certificate files will be saved
	 * @param CertificateFilename The name for the certificate file (without extension)
	 * @param KeyFilename The name for the private key file (without extension)
	 * @param Days Validity period in days (default: 365)
	 * @param Country Country code for certificate (default: "US")
	 * @param Organization Organization name for certificate (default: "ObjectDeliverer")
	 * @param CommonName Common name for certificate (default: "localhost")
	 * @param SubjectAltDnsNames Optional DNS SAN entries (e.g. localhost, example.com)
	 * @param SubjectAltIpAddresses Optional IP SAN entries (e.g. 127.0.0.1)
	 * @return True if certificate generation succeeded, false otherwise
	 */
	static bool GenerateSelfSignedCertificate(
		const FString& OutputDirectory,
		const FString& CertificateFilename = TEXT("server"),
		const FString& KeyFilename = TEXT("server"),
		int32 Days = 365,
		const FString& Country = TEXT("US"),
		const FString& Organization = TEXT("ObjectDeliverer"),
		const FString& CommonName = TEXT("localhost"),
		const TArray<FString>& SubjectAltDnsNames = TArray<FString>(),
		const TArray<FString>& SubjectAltIpAddresses = TArray<FString>()
	);

	/**
	 * Generates a private Certificate Authority (CA) certificate and key.
	 *
	 * @param OutputDirectory The directory where CA files will be saved
	 * @param CertificateFilename The name for the CA certificate file (without extension)
	 * @param KeyFilename The name for the CA private key file (without extension)
	 * @param Days Validity period in days (default: 3650)
	 * @param Country Country code for certificate (default: "US")
	 * @param Organization Organization name for certificate (default: "ObjectDeliverer")
	 * @param CommonName Common name for certificate (default: "ObjectDeliverer Test CA")
	 * @return True if CA certificate generation succeeded, false otherwise
	 */
	static bool GenerateCertificateAuthority(
		const FString& OutputDirectory,
		const FString& CertificateFilename = TEXT("custom_ca"),
		const FString& KeyFilename = TEXT("custom_ca"),
		int32 Days = 3650,
		const FString& Country = TEXT("US"),
		const FString& Organization = TEXT("ObjectDeliverer"),
		const FString& CommonName = TEXT("ObjectDeliverer Test CA")
	);

	/**
	 * Generates a server certificate signed by the provided CA certificate/key pair.
	 *
	 * @param OutputDirectory The directory where server cert/key files will be saved
	 * @param CertificateFilename The name for the server certificate file (without extension)
	 * @param KeyFilename The name for the server private key file (without extension)
	 * @param CaCertificatePath Path to CA certificate file (.crt/.pem)
	 * @param CaPrivateKeyPath Path to CA private key file (.key/.pem)
	 * @param Days Validity period in days (default: 365)
	 * @param Country Country code for certificate (default: "US")
	 * @param Organization Organization name for certificate (default: "ObjectDeliverer")
	 * @param CommonName Common name for certificate (default: "localhost")
	 * @param SubjectAltDnsNames Optional DNS SAN entries
	 * @param SubjectAltIpAddresses Optional IP SAN entries
	 * @return True if server certificate generation succeeded, false otherwise
	 */
	static bool GenerateCertificateSignedByAuthority(
		const FString& OutputDirectory,
		const FString& CertificateFilename,
		const FString& KeyFilename,
		const FString& CaCertificatePath,
		const FString& CaPrivateKeyPath,
		int32 Days = 365,
		const FString& Country = TEXT("US"),
		const FString& Organization = TEXT("ObjectDeliverer"),
		const FString& CommonName = TEXT("localhost"),
		const TArray<FString>& SubjectAltDnsNames = TArray<FString>(),
		const TArray<FString>& SubjectAltIpAddresses = TArray<FString>(),
		const FString& ExtendedKeyUsage = TEXT("serverAuth")
	);

	/**
	 * Extracts the public key hash from a certificate file for use with pinning.
	 * This function reads the certificate file and computes the SHA256 hash of the public key.
	 *
	 * @param CertPath The path to the certificate file (.crt or .pem)
	 * @param OutPublicKeyHash The output public key hash in SHA256 format (xx:xx:xx:...)
	 * @return True if extraction succeeded, false otherwise
	 */
	static bool ExtractPublicKeyHash(const FString& CertPath, FString& OutPublicKeyHash);

	/**
	 * Extracts the public key hash from a certificate file and saves it to a text file.
	 * This is a convenience overload that directly saves the hash to a file.
	 *
	 * @param CertPath The path to the certificate file (.crt or .pem)
	 * @param OutputPath The path where the public key hash will be saved
	 * @return True if extraction and save succeeded, false otherwise
	 */
	static bool ExtractPublicKeyHash(const FString& CertPath, const FString& OutputPath);

private:
	struct FCertificateInfo
	{
		FString Country;
		FString Organization;
		FString CommonName;
		TArray<FString> SubjectAltDnsNames;
		TArray<FString> SubjectAltIpAddresses;
	};

	static bool GenerateCertificateInternal(
		const FString& CertPath,
		const FString& PrivateKeyPath,
		int32 Days,
		const FCertificateInfo& CertInfo
	);
};
