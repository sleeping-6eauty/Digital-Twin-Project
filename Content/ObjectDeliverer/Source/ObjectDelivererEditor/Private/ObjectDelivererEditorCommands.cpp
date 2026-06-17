// Copyright 2019 ayumax. All Rights Reserved.
#include "ObjectDelivererEditorCommands.h"

#define LOCTEXT_NAMESPACE "ObjectDelivererEditor"

void FObjectDelivererEditorCommands::RegisterCommands()
{
	UI_COMMAND(GenerateCertificateCommand,
		"Generate TLS Certificate",
		"Generate a self-signed TLS certificate and private key for development/testing purposes",
		EUserInterfaceActionType::Button,
		FInputChord());
}

#undef LOCTEXT_NAMESPACE
