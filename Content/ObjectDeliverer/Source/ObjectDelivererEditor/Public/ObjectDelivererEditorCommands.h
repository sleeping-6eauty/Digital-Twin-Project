// Copyright 2019 ayumax. All Rights Reserved.
#pragma once

#include "CoreMinimal.h"
#include "Framework/Commands/Commands.h"

class FObjectDelivererEditorCommands : public TCommands<FObjectDelivererEditorCommands>
{
public:
	FObjectDelivererEditorCommands()
		: TCommands<FObjectDelivererEditorCommands>(
			TEXT("ObjectDelivererEditor"),
			NSLOCTEXT("Contexts", "ObjectDelivererEditor", "ObjectDeliverer Plugin"),
			NAME_None,
			FAppStyle::GetAppStyleSetName())
	{
	}

	virtual void RegisterCommands() override;

public:
	TSharedPtr<FUICommandInfo> GenerateCertificateCommand;
};
