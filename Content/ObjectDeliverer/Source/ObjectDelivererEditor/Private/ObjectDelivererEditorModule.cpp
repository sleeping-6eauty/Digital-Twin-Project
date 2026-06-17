// Copyright 2019 ayumax. All Rights Reserved.
#include "ObjectDelivererEditorModule.h"
#include "ObjectDelivererEditorCommands.h"
#include "ObjectDelivererEditorStyle.h"
#include "Utils/ObjectDelivererCertificateGenerator.h"
#include "Framework/MultiBox/MultiBoxBuilder.h"
#include "Framework/MultiBox/MultiBoxExtender.h"
#include "LevelEditor.h"
#include "Misc/MessageDialog.h"
#include "DesktopPlatformModule.h"
#include "IDesktopPlatform.h"
#include "Framework/Application/SlateApplication.h"

#define LOCTEXT_NAMESPACE "FObjectDelivererEditorModule"

void FObjectDelivererEditorModule::StartupModule()
{
	FObjectDelivererEditorStyle::Initialize();

	FObjectDelivererEditorCommands::Register();

	Commands = MakeShareable(new FUICommandList);
	Commands->MapAction(
		FObjectDelivererEditorCommands::Get().GenerateCertificateCommand,
		FExecuteAction::CreateRaw(this, &FObjectDelivererEditorModule::GenerateCertificateAction)
	);

	// Add menu extension
	if (FModuleManager::Get().IsModuleLoaded("LevelEditor"))
	{
		FLevelEditorModule& LevelEditorModule = FModuleManager::GetModuleChecked<FLevelEditorModule>("LevelEditor");

		TSharedRef<FExtender> MenuExtender = MakeShareable(new FExtender());

		MenuExtender->AddMenuExtension(
			"Tools",
			EExtensionHook::After,
			Commands,
			FMenuExtensionDelegate::CreateRaw(this, &FObjectDelivererEditorModule::CreateMenuEntry)
		);

		LevelEditorModule.GetMenuExtensibilityManager()->AddExtender(MenuExtender);
	}
}

void FObjectDelivererEditorModule::ShutdownModule()
{
	FObjectDelivererEditorStyle::Shutdown();
}

void FObjectDelivererEditorModule::CreateMenuEntry(FMenuBuilder& MenuBuilder)
{
	MenuBuilder.AddMenuEntry(
		LOCTEXT("GenerateCertificateMenuLabel", "Generate TLS Certificate"),
		LOCTEXT("GenerateCertificateMenuTooltip", "Generate a self-signed TLS certificate and private key for development/testing"),
		FSlateIcon(),
		FUIAction(
			FExecuteAction::CreateRaw(this, &FObjectDelivererEditorModule::GenerateCertificateAction)
		),
		NAME_None,
		EUserInterfaceActionType::Button
	);
}

void FObjectDelivererEditorModule::GenerateCertificateAction()
{
	// Show directory picker dialog
	FString OutputDirectory;
	IDesktopPlatform* DesktopPlatform = FDesktopPlatformModule::Get();
	if (DesktopPlatform)
	{
		const void* ParentWindowHandle = FSlateApplication::Get().FindBestParentWindowHandleForDialogs(nullptr);
		
		FString DefaultPath = FPaths::ProjectDir();
		
		bool bFolderSelected = DesktopPlatform->OpenDirectoryDialog(
			ParentWindowHandle,
			LOCTEXT("SelectCertificateOutputDirTitle", "Select Certificate Output Directory").ToString(),
			DefaultPath,
			OutputDirectory
		);

		if (!bFolderSelected)
		{
			// User cancelled
			return;
		}
	}
	else
	{
		FMessageDialog::Open(
			EAppMsgCategory::Error,
			EAppMsgType::Ok,
			LOCTEXT("DesktopPlatformNotAvailable", "Failed to open directory dialog. Desktop platform is not available.")
		);
		return;
	}

	if (OutputDirectory.IsEmpty())
	{
		FMessageDialog::Open(
			EAppMsgCategory::Error,
			EAppMsgType::Ok,
			LOCTEXT("InvalidDirectory", "Invalid directory selected.")
		);
		return;
	}

	// Show detailed warning dialog
	FText Title = LOCTEXT("GenerateCertificateTitle", "Generate TLS Certificate");
	FText Message = LOCTEXT("GenerateCertificateMessage", 
		"This will generate a self-signed TLS certificate and private key for development/testing purposes.\n\n"
		"Output Directory: {0}\n\n"
		"SECURITY WARNINGS:\n"
		"• The private key will be stored UNENCRYPTED\n"
		"• Choose a directory OUTSIDE of Content/ to avoid packaging with your game\n"
		"• NEVER commit private keys to version control\n"
		"• Use proper certificates from a trusted CA for production\n"
		"• Delete certificates securely when no longer needed\n\n"
		"Do you want to continue?");
	
	FText FormattedMessage = FText::Format(Message, FText::FromString(OutputDirectory));

	EAppReturnType::Type Result = FMessageDialog::Open(
		EAppMsgCategory::Warning,
		EAppMsgType::YesNo,
		FormattedMessage,
		Title
	);

	if (Result == EAppReturnType::No)
	{
		return;
	}

	// Generate the certificate
	bool bSuccess = UObjectDelivererCertificateGenerator::GenerateSelfSignedCertificate(
		OutputDirectory,
		TEXT("server"),  // Certificate filename
		TEXT("server"),  // Key filename
		365,            // Valid for 1 year
		TEXT("US"),      // Country
		TEXT("ObjectDeliverer"),  // Organization
		TEXT("localhost") // Common name
	);

	if (bSuccess)
	{
		FText SuccessMessage = LOCTEXT("CertificateGenerationSuccess", 
			"Successfully generated TLS certificate and private key!\n\n"
			"Certificate: {0}\n"
			"Private Key: {1}\n\n"
			"IMPORTANT SECURITY NOTES:\n"
			"• Keep the private key file secure and confidential\n"
			"• Add the output directory to .gitignore\n"
			"• NEVER package these files with your game\n"
			"• Obtain proper certificates for production environments");
		
		FText FormattedSuccessMessage = FText::Format(SuccessMessage,
			FText::FromString(FPaths::Combine(OutputDirectory, TEXT("server.crt"))),
			FText::FromString(FPaths::Combine(OutputDirectory, TEXT("server.key"))));

		FMessageDialog::Open(EAppMsgCategory::Info, EAppMsgType::Ok, FormattedSuccessMessage);
	}
	else
	{
		FMessageDialog::Open(
			EAppMsgCategory::Error,
			EAppMsgType::Ok,
			LOCTEXT("CertificateGenerationFailed", "Failed to generate TLS certificate. Check the output log for details.")
		);
	}
}

#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FObjectDelivererEditorModule, ObjectDelivererEditor)
