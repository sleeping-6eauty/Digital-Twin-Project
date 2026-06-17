// Copyright 2019 ayumax. All Rights Reserved.
#include "ObjectDelivererEditorStyle.h"
#include "Styling/SlateStyleRegistry.h"

TSharedPtr<FSlateStyleSet> FObjectDelivererEditorStyle::StyleInstance = nullptr;

void FObjectDelivererEditorStyle::Initialize()
{
	if (!StyleInstance.IsValid())
	{
		StyleInstance = Create();
		FSlateStyleRegistry::RegisterSlateStyle(*StyleInstance);
	}
}

void FObjectDelivererEditorStyle::Shutdown()
{
	if (StyleInstance.IsValid())
	{
		FSlateStyleRegistry::UnRegisterSlateStyle(*StyleInstance);
		StyleInstance.Reset();
	}
}

FName FObjectDelivererEditorStyle::GetStyleSetName()
{
	static FName StyleSetName(TEXT("ObjectDelivererEditorStyle"));
	return StyleSetName;
}

TSharedRef<FSlateStyleSet> FObjectDelivererEditorStyle::Create()
{
	TSharedRef<FSlateStyleSet> Style = MakeShareable(new FSlateStyleSet(GetStyleSetName()));
	Style->SetContentRoot(FPaths::EngineContentDir() / TEXT("Editor/Slate"));
	Style->SetCoreContentRoot(FPaths::EngineContentDir() / TEXT("Slate"));

	return Style;
}

const ISlateStyle& FObjectDelivererEditorStyle::Get()
{
	return *StyleInstance;
}
