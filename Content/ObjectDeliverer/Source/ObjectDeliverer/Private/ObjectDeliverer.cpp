// Copyright 2019 ayumax. All Rights Reserved.

#include "CoreMinimal.h"
#include "Modules/ModuleManager.h"
#include "IObjectDeliverer.h"
#include "SslModule.h"


class FObjectDeliverer : public IObjectDeliverer
{
	/** IModuleInterface implementation */
	virtual void StartupModule() override;
	virtual void ShutdownModule() override;
};

IMPLEMENT_MODULE(FObjectDeliverer, ObjectDeliverer)



void FObjectDeliverer::StartupModule()
{
#if WITH_SSL
	// Preload UE's SSL module on the game thread so worker-thread TLS setup
	// can safely reuse the certificate manager without tripping thread asserts.
	FModuleManager::LoadModuleChecked<FSslModule>("SSL");
#endif
}


void FObjectDeliverer::ShutdownModule()
{
}


