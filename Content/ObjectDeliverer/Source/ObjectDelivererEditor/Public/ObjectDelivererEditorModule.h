// Copyright 2019 ayumax. All Rights Reserved.
#pragma once

#include "CoreMinimal.h"
#include "Modules/ModuleManager.h"
#include "Framework/Commands/Commands.h"
#include "Framework/Commands/UICommandList.h"

class FObjectDelivererEditorModule : public IModuleInterface
{
public:
	virtual void StartupModule() override;
	virtual void ShutdownModule() override;

private:
	void CreateMenuEntry(FMenuBuilder& MenuBuilder);
	void GenerateCertificateAction();

private:
	TSharedPtr<FUICommandList> Commands;
};
